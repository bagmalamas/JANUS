//This function accepts an array of userCerts.
//It contains the Certificates used by a Client to complete a request.
//Each Client is required to submit the main Certificate (masterCert), which must be identical to the Certificate used to Endorse / Commit the request, as well as the individual Certificates (Combined), in the event that he used additional Identities.
//To begin, the Client signs the sent certificates (master + combined) using masterCert's private key in order to create a signed payload for which he must prove that he owns the key used to sign it.
//Then, for each combined identity, he signs the above signature to demonstrate that he possesses the combined identity's private keys.
//This establishes an unbroken chain of signed certificates for which the client demonstrates that he is both familiar with their private keys and the entity that created the userCerts payload.
//To control the preceding process, the validateUserCerts helper function is invoked.
//Once this process is complete, the helper function removeSignaturesFromUserCerts is invoked to remove all signatures from the payload, leaving only remote certificates (Master + Combined).
//This is because, once the signature control process is complete, we remove the signatures to facilitate payload management. 


// MAIN FUNCTION

async getUserValidation(ctx, userCerts) {
        userCerts = jsonParser(userCerts);

        if (Array.isArray(userCerts)) userCerts = userCerts[0];

        if (!userCerts.master)
            return Shim.error(
                response(
                    false,
                    "Wrong certificates structure. Please, contact an administrator"
                )
            );

        try {
            validateUserCerts(ctx, userCerts);
        } catch (err) {
            return Shim.error(response(false, err.message));
        }

        // Validation passed successfully - Thus, the signatures are not needed anymore
        userCerts = removeSignaturesFromUserCerts(userCerts);

        if (!Array.isArray(userCerts)) {
            return Shim.error(
                Buffer.from(`User's validation parameters error`)
            );
        }

        const proxyStakeholdersKey = Stakeholder.makeKey([
            constants.proxyStakeholders,
        ]);
        const proxyStakeholdersInstance = await ctx.stakeholderManager.get(
            proxyStakeholdersKey
        );

        const [certAttrs, tempAttrs] = [{}, {}];

        for (const userCert of userCerts) {
            // To constructCert δημιουργεί ένα X.509 Cert. Object από το οποίο μπορούμε να αντλούμε τις πληροφορίες ενός Certificate
            const constructedCert = constructCert(userCert);
            const stakeholder =
                constructedCert.issuer.organizationName.toLowerCase();

            // Checks if the stakeholder exists or if revoked
            const stakeholderExists =
                proxyStakeholdersInstance.isKnownStakeholder(stakeholder);

            if (!stakeholderExists)
                return Shim.error(
                    response(
                        false,
                        `Organization ${stakeholder} either does not exist or is revoked`
                    )
                );

            const certificateValidation = await checkClientCertificate(
                ctx,
                constructedCert
            );

            if (!certificateValidation.condition)
                return Shim.error(certificateValidation);

            const CRLKey = TrustFile.makeKey([constants.indexCRL, stakeholder]);
            const CRLDoc = await ctx.trustFileManager.get(CRLKey);

            if (!CRLDoc.isValidFile)
                return Shim.error(
                    response(
                        false,
                        "Internal error. Communicate with the System's Administrator"
                    )
                );

            // The actual CRL data is nested under CRLDoc.data
            const CRLData = CRLDoc.data;

            const isCertRevoked = checkCertRevokedByCRL(
                CRLData,
                constructedCert
            );

            if (!isCertRevoked.condition)
                return Shim.success(response(false, isCertRevoked.message));

            const stakeholderData =
                await proxyStakeholdersInstance.getStakeholderByName(
                    ctx,
                    stakeholder
                );

            const stakeholderMSP = stakeholderData.msp.toUpperCase();

            if (!certAttrs[stakeholderMSP]) certAttrs[stakeholderMSP] = {};

            const extraCertAttrs = getExtraCertAttrs(constructedCert);

            Object.keys(extraCertAttrs).forEach((type) => {
                certAttrs[stakeholderMSP][type] =
                    typeof extraCertAttrs[type] !== "object"
                        ? (certAttrs[stakeholderMSP][type],
                          extraCertAttrs[type])
                        : {
                              ...(certAttrs[stakeholderMSP][type] || {}),
                              ...extraCertAttrs[type],
                          };
            });

            tempAttrs[stakeholderMSP] = {
                ...tempAttrs[stakeholderMSP],
                ...(await getTempACLAttrs(
                    ctx,
                    certAttrs[stakeholderMSP].GID,
                    stakeholderData
                )),
            };
        }

        const combinedAttrs = combineAttributes(ctx, certAttrs, tempAttrs);

        return Shim.success(Buffer.from(JSON.stringify(combinedAttrs)));
    }


// HELPER FUNCTIONS

const removeSignaturesFromUserCerts = (userCerts) => [
    userCerts.master.certificate,
    ...userCerts.combined.map((identity) => identity.certificate),
];

const validateUserCerts = (ctx, userCerts) => {
    const cid = new ClientIdentity(ctx.stub);
    const invokerCert = cid.getIDBytes().toString("utf-8"); // The Invoker's certificate

    let {
        master: { certificate: masterCert, signature: masterSignature },
        combined: combinedIdentities = [],
    } = userCerts;

    // Validate that the master cert is invoker's cert
    const masterCertIsInvokersCert = matchStrings(
        masterCert,
        invokerCert,
        true
    );

    if (!masterCertIsInvokersCert)
        throw new Error("Invalid Master Identity certificate");

    // Validate the master signature against the master Cert
    masterSignature = arrayToUINT8Array(masterSignature);

    const constructedMasterCert = constructCert(
        Buffer.from(masterCert, "utf-8").toString("base64")
    );

    const userCertsData = [
        masterCert,
        ...combinedIdentities.map((identity) => identity.certificate),
    ];

    const invokerHoldsPK = constructedMasterCert.publicKey.verify(
        Buffer.from(userCertsData, "binary"),
        Buffer.from(masterSignature, "binary"),
        "sha256"
    );

    if (!invokerHoldsPK) throw new Error("You do not own the master identity");

    // Validate that the user is the owner of the combined identities
    const invokerOwnsCombinedIdent = combinedIdentities.every((identity) => {
        const combinedIdentCert = identity.certificate;
        const combinedIdentSignature = arrayToUINT8Array(identity.signature);

        const constructedIdentityCert = constructCert(
            Buffer.from(combinedIdentCert, "utf-8").toString("base64")
        );

        return constructedIdentityCert.publicKey.verify(
            Buffer.from(masterSignature, "binary"),
            Buffer.from(combinedIdentSignature, "binary"),
            "sha256"
        );
    });

    if (!invokerOwnsCombinedIdent)
        throw new Error("Error with your combined identities");

    return;
};

const checkCertRevokedByCRL = (crlRecord, certificate) => {
    const constructedCRL = constructCRL(crlRecord);

    if (
        !constructedCRL.revokedCertificates ||
        constructedCRL.revokedCertificates === 0
    ) {
        return response(true, "The certificate is valid");
    }

    for (const { userCertificate } of constructedCRL.revokedCertificates) {
        let revokedCertSerialNumber = pvutils.bufferToHexCodes(
            userCertificate.valueBlock.valueHex
        );

        if (certificate.serialNumber === revokedCertSerialNumber) {
            return response(false, "The certificate is REVOKED");
        }
    }

    return response(true, "The certificate is VALID");
};

const getExtraCertAttrs = (constructedCert) => {
    const extension = constructedCert.extensions.find(
        (ext) => ext.oid === "1.2.3.4.5.6.7.8.1"
    );
    // const subject = constructedCert.subject;
    let attrs = {};
    if (extension) {
        const str = extension.value.toString();
        const obj = JSON.parse(str);
        [attrs.ROLES, attrs.EXTRA] = [{}, {}];

        for (let attr in obj.attrs) {
            let attribute = attr.toUpperCase();
            if (attribute.startsWith("ROLE")) {
                attrs.ROLES[attribute] = obj.attrs[attr].toUpperCase();
            } else if (attribute.match("GID")) {
                attrs.GID = obj.attrs[attr];
            } else {
                attrs.EXTRA[attribute] = obj.attrs[attr].toUpperCase();
            }
        }
    }

    return attrs;
};

const getTempACLAttrs = async (ctx, GID, stakeholder) => {
    const attributes = {};

    const tempACLKey = TrustFile.makeKey([
        constants.indexACL,
        stakeholder.name,
    ]);

    const tempACLInstance = await ctx.trustFileManager.get(tempACLKey);

    if (!tempACLInstance) return {};

    const tempACL = tempACLInstance.getData();

    if (tempACL[GID]) {
        const isCARevoked = await checkCARevoked(ctx, stakeholder.name);
        if (isCARevoked.condition) return {};

        const accessValues = tempACL[GID];

        for (const attr in accessValues) {
            const attributeName = attr.toUpperCase();
            attributes[attributeName] = accessValues[attr];
        }
    }
    return attributes;
};

const checkClientCertificate = async (ctx, constructedCert) => {
    const TrustFile = require("../types/trust_anchors/trustFile");

    const currentTime = timestampToMilliseconds(ctx.stub.getTxTimestamp());

    if (constructedCert.validTo.getTime() < currentTime)
        return response(false, "The certificate has expired");

    const clientOrg = constructedCert.issuer.organizationName.toLowerCase();

    // Get every indexCert record of the stakeholder
    const rootCACertInstanceHistory = await ctx.trustFileManager.getHistory([
        constants.indexCert,
        clientOrg,
    ]);

    if (rootCACertInstanceHistory) {
        const foundData = await Promise.all(
            rootCACertInstanceHistory.map(async (historyInstance) => {
                const certInstance = historyInstance.Value;
                const timestamp = historyInstance.Timestamp;

                const { data: caCertData, isRevoked } = certInstance;

                const constructedCACert = constructCert(caCertData);

                if (
                    matchStrings(
                        constructedCert.authorityKeyIdentifier,
                        constructedCACert.subjectKeyIdentifier,
                        true
                    )
                ) {
                    if (isRevoked)
                        return response(false, {
                            timestamp,
                            reason: `Your organization is revoked [ORGANIZATION: ${constructedCert.issuer.organizationName.toUpperCase()}]`,
                        });

                    const CRLDocKey = TrustFile.makeKey([
                        constants.indexCRL,
                        constructedCert.issuer.organizationName.toLowerCase(),
                    ]);
                    const CRLDocInstance = await ctx.trustFileManager.get(
                        CRLDocKey
                    );
                    const CRLDoc = CRLDocInstance.data;

                    const isCACertRevoked = checkCertRevokedByCRL(
                        CRLDoc,
                        constructedCACert
                    );

                    if (!isCACertRevoked.condition)
                        return response(false, {
                            timestamp,
                            reason: "The root Certificate is revoked",
                        });

                    const isClientCertRevoked = checkCertRevokedByCRL(
                        CRLDoc,
                        constructedCert
                    );

                    if (!isClientCertRevoked.condition)
                        return response(false, {
                            timestamp,
                            reason: "The Client's Certificate is revoked",
                        });

                    const subjectKeyIdentifierMatch =
                        constructedCert.verifySubjectKeyIdentifier();

                    if (!subjectKeyIdentifierMatch)
                        return response(false, {
                            timestamp,
                            reason: "Error in Subject Key identifier",
                        });

                    if (
                        !(
                            constructedCACert.validFrom <=
                            constructedCert.validFrom
                        ) ||
                        !(constructedCert.validTo <= constructedCACert.validTo)
                    )
                        return response(false, {
                            timestamp,
                            reason: "The certificate has expired or is not active",
                        });

                    const signatureNotNull =
                        constructedCACert.checkSignature(constructedCert); // If `null`, then the signature is valid

                    if (signatureNotNull)
                        return response(false, {
                            timestamp,
                            reason: "The signature of the certificate is malformed",
                        });

                    return response(true, {
                        timestamp,
                        reason: "The certificate is valid",
                    });
                }
            })
        );

        const isCertActive = foundData
            .filter((response) => typeof response !== "undefined")
            .sort((a, b) => b.message.timestamp - a.message.timestamp)[0];

        return response(isCertActive.condition, isCertActive.message.reason);
    }

    return response(false, "The certificate is invalid");
};

const combineAttributes = (ctx, certAttrs, tempAttrs) => {
    const cid = new ClientIdentity(ctx.stub);

    let combinedAttrs = {};

    for (const authority in certAttrs) {
        for (const combinedAttrType of ["ROLES", "EXTRA", "TEMPORALROLES"]) {
            combinedAttrs[combinedAttrType] =
                combinedAttrs[combinedAttrType] || {};
            combinedAttrs[combinedAttrType][authority] =
                combinedAttrs[combinedAttrType][authority] || {};
        }

        for (const certAttr in certAttrs[authority].ROLES) {
            combinedAttrs.ROLES[authority][
                certAttrs[authority].ROLES[certAttr]
            ] = {
                ROLE: certAttrs[authority].ROLES[certAttr],
                TEMPORAL_ROLE: false,
            };
        }

        for (const certAttr in certAttrs[authority].EXTRA) {
            combinedAttrs.EXTRA[authority][certAttr] = {
                extraAttribute: certAttrs[authority].EXTRA[certAttr],
            };
        }

        if (combinedAttrs.GID) {
            if (combinedAttrs.GID !== certAttrs[authority].GID)
                return response(false, "Certificates' GIDS do not match");
            break;
        }

        if (!certAttrs[authority].GID)
            return response(
                false,
                "The Certificate(s) does not have a GID attribute"
            );

        if (!cid.assertAttributeValue("GID", certAttrs[authority]["GID"])) {
            return response(
                false,
                `You loaded a Certificate that you do not own`
            );
        }

        combinedAttrs.GID = certAttrs[authority].GID;
    }

    for (const authority in tempAttrs) {
        for (const attribute in tempAttrs[authority]) {
            combinedAttrs.TEMPORALROLES[authority][attribute] = {
                ROLE: attribute,
                AUTHORITY: authority,
                TEMPORAL_ROLE: true,
                DATA: tempAttrs[authority][attribute],
            };
        }
    }

    return response(true, combinedAttrs);
};
