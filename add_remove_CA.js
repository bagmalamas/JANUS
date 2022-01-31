// Ένα Voting χωρίζεται σε δύο μέρη: Στο Smart Contract που επιθυμεί να ξεκινήσει ένα Voting (TMSC/LSC) καθώς και στο Smart Contract που διαχειρίζεται τα Votings (PSC)
// Για την εκκίνηση ενός Voting, πρέπει να κληθεί το majorityConsentInit function που αναπτύσσεται στο PSC (καλείται από το ενδιαφερόμενο Smart Contract, όχι τον Client!).
// Όταν ένα Voting ολοκληρώνεται, τότε το PSC καλεί το majorityUpdate function το οποίο ΕΙΝΑΙ ΑΠΑΡΑΙΤΗΤΟ να βρίσκεται σε κάθε Smart Contract για το οποίο μπορούν να δημιουργούνται Votings (TMSC/LSC)

// Όταν ένας Client επιθυμεί να ψηφίσει σε ενα Voting, καλεί το majorityClientVote function που βρίσκεται στο PSC
// Όταν ολοκληρώνεται ένα Voting, πρέπει να κληθεί το updateElection function που βρίσκεται στο PSC (καλείται από το Inter-Blockchain API)

// MAIN FUNCTIONS

// TMSC

async addCA(ctx, orgMSP, caCert, caCRL, tempACL) {
        const cid = new ClientIdentity(ctx.stub);

        // Check if invoker's Org is revoked
        const ownerOrgIsRevoked = await checkIfStakeholderIsRevoked(
            ctx,
            cid.getMSPID()
        );

        if (ownerOrgIsRevoked.status)
            return Shim.error(ownerOrgIsRevoked.message);
        // End of check

        const hasAccessToFN = accessAudit(cid, [["CA-ADMIN"]]);
        if (!hasAccessToFN.hasAccess) return Shim.error(hasAccessToFN.message);

        [orgMSP, caCert, caCRL, tempACL] = [
            jsonParser(orgMSP),
            jsonParser(caCert),
            jsonParser(caCRL),
            jsonParser(tempACL),
        ];

        const domainStakeholdersInstance =
            await returnDomainStakeholdersInstance(ctx);
        let { stakeholders, domain: initiatorOrgDomain } =
            domainStakeholdersInstance.getStakeholdersWithDetails();

        stakeholders =
            domainStakeholdersInstance.removeRevokedStakeholdersFromList(
                stakeholders
            );

        const constructedCert = constructCert(caCert);
        const [newOrganizationName, newCADomain] = [
            constructedCert.issuer.organizationName,
            constructedCert.issuer.organizationalUnitName.toUpperCase(),
        ];

        const stakeholderNotInState = Object.values(stakeholders).every(
            (stakeholder) =>
                !matchStrings(newOrganizationName, stakeholder.name)
        );

        if (!stakeholderNotInState) {
            const stakeholderInfo = Object.values(stakeholders).find(
                (stakeholder) =>
                    matchStrings(newOrganizationName, stakeholder.name)
            );

            if (!stakeholderInfo.isRevoked)
                return Shim.error(
                    `Stakeholder ${newOrganizationName} already exists and is not revoked`
                );
        }

        if (!matchStrings(initiatorOrgDomain, newCADomain))
            return Shim.error(
                `Stakeholder is from a different Domain. Check the Organizational Unit Name of the appended CA Certificate [INVOKER: ${initiatorOrgDomain}, NEW CA: ${newCADomain}]`
            );

        for (const document of [caCert, caCRL, tempACL]) {
            const file = TrustFile.createInstance();
            await file.defineFile(ctx, document, true);

            if (!file.isValidFile)
                return Shim.error(`The file is invalid. ${file.error}`);
        }

        tempACL = Buffer.from(tempACL, "base64").toString("utf-8");
        tempACL = jsonParser(tempACL);

        if (!matchStrings(tempACL["ORGANIZATION"], newOrganizationName))
            return Shim.error(
                "The ACL document is for a different organization"
            );

        tempACL = Buffer.from(JSON.stringify(tempACL), "utf-8").toString(
            "base64"
        );

        const electionInstance = Election.createInstance(
            "add_ca",
            initiatorOrgDomain,
            [orgMSP, caCert, caCRL, tempACL], // = data
            `Addition of ${newOrganizationName.toUpperCase()} [DOMAIN: ${newCADomain}]`,
            stakeholders
        );

        // Contacts the PSC in order to start a new Election
        const [pscData, pscError] = await ctx.electionManager.startElection(
            cid,
            electionInstance
        );

        if (pscError) return Shim.error(pscError);

        electionInstance.setElectionID(pscData);
        electionInstance.createStateKey();

        await ctx.electionManager.add(electionInstance);

        new Event(ctx, "ElectionInitiated", pscData).assignEvent();

        return Shim.success(
            Buffer.from(
                `Successfully started an Election [Election ID: ${electionInstance.electionInfo.electionID}]`
            )
        );
}

async removeCA(ctx, caName) {
        const cid = new ClientIdentity(ctx.stub);

        // Check if invoker's Org is revoked
        const ownerOrgIsRevoked = await checkIfStakeholderIsRevoked(
            ctx,
            cid.getMSPID()
        );

        if (ownerOrgIsRevoked.status)
            return Shim.error(ownerOrgIsRevoked.message);
        // End of check

        caName = jsonParser(caName.replace(/\s/g, "-"));

        const hasAccessToFN = accessAudit(cid, [["CA-ADMIN"]]);
        if (!hasAccessToFN.hasAccess) return Shim.error(hasAccessToFN.message);

        const stakeholdersKey = Stakeholder.makeKey([
            constants.proxyStakeholders,
        ]);
        const stakeholderInstance = await ctx.stakeholderManager.get(
            stakeholdersKey
        );

        const isKnownStakeholder =
            stakeholderInstance.isKnownStakeholder(caName);

        if (!isKnownStakeholder)
            return Shim.error(`Unknown stakeholder [Stakeholder: ${caName}]`);

        const initiatorStakeholderIsRemovedStakeholder =
            await stakeholderInstance.stakeholderIsInvokerStakeholder(
                ctx,
                cid.getMSPID(),
                caName
            );

        if (initiatorStakeholderIsRemovedStakeholder)
            return Shim.error(
                `Can not ask to remove the Organization that you belong to`
            );

        stakeholderInstance.removeStakeholderFromStakeholders(caName);

        const { stakeholders, domain } =
            stakeholderInstance.getStakeholdersWithDetails();

        stakeholderInstance.removeRevokedStakeholdersFromList(stakeholders);

        const electionInstance = Election.createInstance(
            "remove_ca",
            domain,
            [caName], // = data
            `Removal of ${caName.toUpperCase()} [DOMAIN: ${domain}]`,
            stakeholders
        );

        const [pscData, pscError] = await ctx.electionManager.startElection(
            cid,
            electionInstance
        );

        if (pscError) return Shim.error(pscError);

        electionInstance.setElectionID(pscData);
        electionInstance.createStateKey();

        await ctx.electionManager.add(electionInstance);

        new Event(ctx, "ElectionInitiated", pscData).assignEvent();

        return Shim.success(
            Buffer.from(
                `Successfully started an Election [Election ID: ${electionInstance.electionInfo.electionID}]`
            )
        );
}

// Καλείται από το PSC
async majorityUpdate(ctx, payload) {
        const { electionID, electionApproved, canStillReachConsensus } =
            JSON.parse(payload);

        const electionKey = Election.makeKey([electionID]);
        const electionInstance = await ctx.electionManager.get(electionKey);

        if (!electionInstance)
            return Shim.success(
                bufferResponse(
                    true,
                    `Election finished unsuccessfully [ELECTION ID: ${electionID}]`
                )
            );

        if (!canStillReachConsensus && !electionApproved)
            await ctx.electionManager.removeInstance(electionKey);

        if (electionApproved) {
            await ctx.electionManager.updateFromElection(ctx, electionInstance);
            await ctx.electionManager.removeInstance(electionKey);
        }

        return Shim.success(
            bufferResponse(
                true,
                `Election finished successfully [ELECTION ID: ${electionID}]`
            )
        );
}

// LSC

async retrieveLogInit(ctx, retrieveDetails) {
        const isStakeholderRevoked = await isInvokerStakeholderRevoked(ctx);
        if (isStakeholderRevoked.condition)
            return Shim.error(isStakeholderRevoked.message);

        const cid = new ClientIdentity(ctx.stub);

        const hasAccessToFN = accessAudit(cid, [["AUDITOR"]]);
        if (!hasAccessToFN.hasAccess) return Shim.error(hasAccessToFN.message);

        const invokerMSPID = cid.getMSPID();
        retrieveDetails = JSON.parse(retrieveDetails.toString());

        const type = retrieveDetails.type;
        const domain = retrieveDetails.domain.toUpperCase();

        const isDomainAvailable = new RegExp(
            constants.AVAILABLE_DOMAINS.join("|"),
            "i"
        );

        if (!isDomainAvailable.test(domain))
            return Shim.error(
                `Unknown domain - ${domain} is unknown to the System`
            );

        if (
            !new RegExp(constants.AVAILABLE_REQUEST_TYPES.join("|"), "i").test(
                type
            )
        )
            return Shim.error(
                `Unknown request type - ${type} is unknown to the System`
            );

        const requestData = {
            type: type,
            audience: domain,
            auditor: deriveIdCNFromCID(cid),
            msp: invokerMSPID,
            status: false,
            approved: false,
            validUntil: null,
        };

        const electionInstance = Election.createInstance(
            "logs",
            domain,
            requestData,
            `Access to Logs by ${invokerMSPID}`,
            {}
        );

        const [pscData, pscError] = await ctx.electionManager.startElection(
            cid,
            electionInstance
        );

        if (pscError) return Shim.error(pscError);

        electionInstance.setElectionID(pscData);

        electionInstance.createStateKey([
            constants.RETRIEVE_LOG_REQUEST,
            cid.getMSPID(),
            electionInstance.electionInfo.electionID,
        ]);

        electionInstance.setDataNonce(electionInstance.electionInfo.electionID);

        await ctx.electionManager.add(electionInstance);

        new Event(ctx, "ElectionInitiated", pscData).assignEvent();

        return Shim.success(
            bufferResponse(
                true,
                `Successfully started an Election [Election ID: ${electionInstance.electionInfo.electionID}]`
            )
        );
}

async majorityUpdate(ctx, payload) {
        const {
            electionID,
            electionApproved,
            canStillReachConsensus,
            creator, // = Creator Org (MSP)
        } = jsonParser(payload);

        const electionKey = Election.makeKey([
            constants.RETRIEVE_LOG_REQUEST,
            creator,
            electionID,
        ]);

        const electionInstance = await ctx.electionManager.get(electionKey);

        if (electionApproved) {
            const currentTime = timestampToMilliseconds(
                ctx.stub.getTxTimestamp()
            );
            electionInstance.data.status = true;
            electionInstance.data.approved = true;
            electionInstance.data.validUntil = new Date(
                currentTime + 24 * 60 * 60 * 1000
            ); // This is valid for 1 day - e.g. for 3 days: 3 * 24 * 60 * 60 * 1000 = 3 days
        } else {
            if (!canStillReachConsensus) {
                electionInstance.data.status = true;
                electionInstance.data.approved = false;
            }
        }

        await ctx.electionManager.updateInstance(electionInstance);

        return Shim.success(
            Buffer.from(
                bufferResponse(
                    true,
                    `The Election finished successfully [REQID: ${electionID}]`
                )
            )
        );
}

// PSC

async majorityConsentInit(ctx, payload) {
        // For some reason, there is a bug (in HF) and an optional arg (stakeholders = {}) cannot be assigned - Thus, the others CCs should include an empty stakeholders' Object ({})
        // The problem stems from the fact that an invocation can also happen from the TMSC, so the CC won't be able to complete the request (with error: same TX IDs)
        const cid = new ClientIdentity(ctx.stub);

        const hasAccessToFN = accessAudit(cid, [["CA-ADMIN"], ["AUDITOR"]]);
        if (!hasAccessToFN.hasAccess) return Shim.error(hasAccessToFN.message);

        payload = JSON.parse(payload);
        const invokerMSPID = cid.getMSPID();

        const electionInstance = Election.createInstance(payload);

        // In order to avoid duplicate Elections
        // e.g. A Stakeholder (1) asks to remove another Stakeholder (2), while in the meantime, a third Stakeholder (3)
        // asks to remove the second (2) Stakeholder
        // all the ACTIVE (and ONLY the ACTIVE) Elections are examined in case that any of them carries the same dataHash
        const currentActiveElections = await fetchPartialCompositeKey(
            ctx,
            constants.ACTIVE_ELECTION,
            []
        );

        for (const election of currentActiveElections) {
            const electionID = ctx.stub.splitCompositeKey(election.Key)
                .attributes[1];

            const activeElectionKey = Election.makeKey([electionID]);
            const activeElection = await ctx.electionManager.get(
                activeElectionKey
            );

            if (!activeElection) continue;

            if (
                matchStrings(
                    activeElection.dataHash,
                    electionInstance.dataHash,
                    true
                )
            )
                return Shim.error(
                    `An active Election already exists [ELECTION ID: ${activeElection.electionID}, ELECTION START DATE: ${activeElection.startDate}, ELECTION END DATE: ${activeElection.validUntil}, INITIATOR: ${activeElection.creator}]`
                );
        }

        const [stakeholdersData, stakeholdersDataErr] = await promiseHandler(
            getDomainStakeholders(
                ctx,
                invokerMSPID,
                electionInstance.getAudience(),
                false,
                electionInstance.getStakeholders(),
                true
            )
        );

        if (stakeholdersDataErr) return Shim.error(stakeholdersDataErr.message);

        const stakeholders = stakeholdersData[0];

        electionInstance.prepareElection(ctx, stakeholders, invokerMSPID);
        electionInstance.createStateKey();

        const activeElectionKey = ctx.stub.createCompositeKey(
            constants.ACTIVE_ELECTION,
            [invokerMSPID, electionInstance.electionID]
        );

        try {
            await ctx.electionManager.addState(electionInstance);
            await ctx.stub.putState(activeElectionKey, Buffer.alloc(1));
        } catch (err) {
            return Shim.error(response(false, "Could not create an Election"));
        }

        for (const stakeholder in electionInstance.stakeholders) {
            const { msp } = electionInstance.stakeholders[stakeholder];

            if (matchStrings(invokerMSPID, msp)) continue;

            // Creates the `envelopes` for the votes (one for every organization)
            const ballot = Ballot.createInstance(
                msp,
                electionInstance.electionID
            );

            await ctx.ballotManager.add(ballot);
        }

        const eventData = electionInstance.constuctElectionEvent(ctx);
        return Shim.success(bufferResponse(true, eventData));
}

async majorityClientVote(ctx, authoritySign) {
        const cid = new ClientIdentity(ctx.stub);

        const hasAccessToFN = accessAudit(cid, [["CA-ADMIN"]]);
        if (!hasAccessToFN.hasAccess) return Shim.error(hasAccessToFN.message);

        const invokerMSPID = cid.getMSPID();
        const invoker = deriveIdCNFromCID(cid);

        authoritySign = JSON.parse(authoritySign);

        let authoritySignData;
        try {
            authoritySignData = new AuthoritySign(authoritySign);
        } catch (err) {
            return Shim.error(err.message);
        }

        const ballotKey = Ballot.makeKey([
            invokerMSPID,
            authoritySignData.nonce,
        ]);
        const ballotInstance = await ctx.ballotManager.get(ballotKey);

        if (!ballotInstance)
            return Shim.error(
                `An Election does not exist or you are not eligible to vote [ELECTION ID: ${authoritySignData.nonce}]`
            );

        if (ballotInstance.signed)
            return Shim.error(
                `You have already voted [ELECTION ID: ${authoritySignData.nonce}}]`
            );

        const electionKey = Election.makeKey([authoritySignData.nonce]);
        const electionInstance = await ctx.electionManager.get(electionKey);

        if (!electionInstance)
            return Shim.error(
                `The Election was not found - Communicate with the System's Administrator [ELECTION ID: ${authoritySignData.nonce}]`
            );

        if (matchStrings(invokerMSPID, electionInstance.creator, true))
            return Shim.error(
                `Can not vote to an Election that your Organization has started, MSP IDs match error: [CREATOR: ${electionInstance.creator}, YOU: ${invokerMSPID}]`
            );

        const currentTime = timestampToDate(ctx.stub.getTxTimestamp());

        if (!(currentTime < new Date(electionInstance.validUntil)))
            return Shim.error("The Election period is over");

        const derivedPublicCertificate = cid.getIDBytes().toString("base64"); // The certificate of the invoker

        const [signChallenge, signChallengeErr] = await promiseHandler(
            validateSignChallenge(
                ctx,
                derivedPublicCertificate,
                electionInstance.challengeData,
                authoritySignData.signature
            )
        );

        if (signChallengeErr)
            return Shim.error(
                "Could not validate the signature",
                signChallengeErr.message
            );

        if (!signChallenge.condition)
            return Shim.error(
                `Invalid signature, error ${signChallenge.message}`
            );

        try {
            ballotInstance.castVote(
                ctx,
                invoker,
                authoritySignData.approved,
                authoritySignData.signature
            );

            await ctx.ballotManager.updateInstance(ballotInstance);
        } catch (err) {
            return Shim.error(
                `Could not append the approval to the Election with ID: ${authoritySignData.nonce}`
            );
        }

        const eventData = {
            electionType: electionInstance.electionType,
            electionID: authoritySignData.nonce,
            voter: invokerMSPID,
        };

        new Event(ctx, "BallotUpdated", eventData).assignEvent();

        return Shim.success(
            Buffer.from(
                `Successful Vote [ELECTION ID: ${
                    authoritySignData.nonce
                }, APPROVAL: ${
                    authoritySignData.approved ? "APPROVED" : "DECLINED"
                }]`
            )
        );
}

async updateElection(ctx, electionID) {
        const cid = new ClientIdentity(ctx.stub);
        const invokerMSPID = cid.getMSPID();

        const [consentCheck, consentCheckErr] = await promiseHandler(
            majorityConsentCheck(ctx, electionID, invokerMSPID)
        );

        if (consentCheckErr) return Shim.error(consentCheckErr.message);

        const electionApproved = consentCheck.condition;
        const { electionData, canStillReachConsensus } = consentCheck.message;

        if (!verifyElectionOwnership(ctx, electionData.creator, invokerMSPID))
            return Shim.error(
                `Your organization does not own this election [ELECTION ID: ${electionID}]`
            );

        const currentTime = timestampToDate(ctx.stub.getTxTimestamp());

        if (
            electionApproved ||
            (!electionApproved && !canStillReachConsensus) ||
            !(currentTime < new Date(electionData.validUntil))
        ) {
            // Means that the election has ended
            const activeElectionCompositeKey = ctx.stub.createCompositeKey(
                constants.ACTIVE_ELECTION,
                [invokerMSPID, electionID]
            );

            try {
                await ctx.stub.deleteState(activeElectionCompositeKey);
            } catch (err) {
                return Shim.error("Could not remove the Active Election");
            }

            const chaincodeToCall =
                electionData.electionType === "logs" ? "LSC" : "TMSC";

            const invokePayload = {
                electionID: electionData.electionID,
                electionApproved,
                canStillReachConsensus,
                creator: electionData.creator,
            };

            const CCInstance =
                chaincodeInstances[chaincodeToCall].majorityUpdate(ctx);

            await CCInstance.makeContact([invokePayload]);
            const [CCResponse, CCResponseErr] = [
                CCInstance.response,
                CCInstance.error,
            ];

            if ((CCResponse && !CCResponse.condition) || CCResponseErr)
                return Shim.error(
                    CCResponse ? CCResponse.message : CCResponseErr.message
                );

            new Event(ctx, "ElectionEnded", electionID).assignEvent();

            return Shim.success(
                bufferResponse(true, "The Election ended successfully")
            );
        }
        new Event(ctx, "ElectionStillInProgress", electionID).assignEvent();

        return Shim.success(
            bufferResponse(true, "The Election is still in progress")
        );
    }