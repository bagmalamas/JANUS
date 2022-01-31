# This is the Access Control Smart Contract used in the Domain Blockchains

// MAIN FUNCTION
async policyEnf(ctx, verified_attributes, data_id) {
        let shouldForwardToKSSC = false;

        const [verifiedAttributes, dataID] = [
            jsonParser(verified_attributes),
            jsonParser(data_id),
        ];

        const ROLES = verifiedAttributes.ROLES || {};

        const dataIDType = Object.keys(dataID)[0];
        const dataIDParameters = dataID[dataIDType].parameters;
        const dataIDOrganization =
            dataID[dataIDType].organization || "No organization defined";

        switch (dataIDType) {
            case "data_00": {
                //POSTER: Doctor - TARGET: Hospitals
                const patientUUID = dataIDParameters.uuid;
                for (const ORGANIZATION_MSP in ROLES) {
                    if (ROLES[ORGANIZATION_MSP].DOCTOR) {
                        const TEMPORALROLES = getTemporalRolesOfOrgMSP(
                            verifiedAttributes,
                            ORGANIZATION_MSP
                        );

                        let isOnDuty = false;
                        const patients =
                            accessNestedJSON(
                                TEMPORALROLES,
                                "DOCTOR_OF",
                                "DATA"
                            ) || [];

                        const hasPatient = patients.includes(patientUUID);

                        if (!hasPatient)
                            isOnDuty = checkIfActiveEmployee(
                                TEMPORALROLES,
                                "DOCTOR"
                            );

                        if (hasPatient || isOnDuty) shouldForwardToKSSC = true;

                        break;
                    }
                }
                break;
            }
            case "data_01": //POSTER: Technician - TARGET: Manufacturer
                if (!dataIDOrganization) break;
                shouldForwardToKSSC = Object.keys(ROLES).some(
                    (ORGANIZATION_MSP) => {
                        if (ROLES[ORGANIZATION_MSP].TECHNICIAN) {
                            const TEMPORALROLES = getTemporalRolesOfOrgMSP(
                                verifiedAttributes,
                                ORGANIZATION_MSP
                            );
                            const isActiveTechnician = checkIfActiveEmployee(
                                TEMPORALROLES,
                                "TECHNICIAN"
                            );
                            return isActiveTechnician;
                        }
                        return false;
                    }
                );
                break;
            case "data_02": //POSTER: Researcher - TARGET: Manufacturer
                if (!dataIDOrganization) break;
                for (const ORGANIZATION_MSP in ROLES) {
                    if (ROLES[ORGANIZATION_MSP].RESEARCHER) {
                        const TEMPORALROLES = getTemporalRolesOfOrgMSP(
                            verifiedAttributes,
                            ORGANIZATION_MSP
                        );

                        const isActiveResearcher = checkIfActiveEmployee(
                            TEMPORALROLES,
                            "RESEARCHER"
                        );

                        isActiveResearcher
                            ? (shouldForwardToKSSC = true)
                            : (shouldForwardToKSSC = false);
                        break;
                    }
                }
                break;
            case "data_03": //POSTER: Researcher - TARGET: Hospitals
                for (const ORGANIZATION_MSP in ROLES) {
                    if (ROLES[ORGANIZATION_MSP].RESEARCHER) {
                        const TEMPORALROLES = getTemporalRolesOfOrgMSP(
                            verifiedAttributes,
                            ORGANIZATION_MSP
                        );

                        const isActiveResearcher = checkIfActiveEmployee(
                            TEMPORALROLES,
                            "RESEARCHER"
                        );

                        isActiveResearcher
                            ? (shouldForwardToKSSC = true)
                            : (shouldForwardToKSSC = false);
                        break;
                    }
                }
                break;
            case "data_04": //POSTER: Manufacturing_Staff - TARGET: Hospitals
                for (const ORGANIZATION_MSP in ROLES) {
                    if (ROLES[ORGANIZATION_MSP].MANUFACTURING_STAFF) {
                        shouldForwardToKSSC = true;
                        break;
                    }
                }
                break;
            default:
                ctx.stub.setEvent(
                    "PolicyEnforcementDeclined",
                    Buffer.from(JSON.stringify(false))
                );
        }

        const { GID } = verifiedAttributes;

        const policyEnforcementDetails = {
            GID,
            policyEnforcementDetails: {
                data_type: dataIDType,
                data_value: dataIDParameters,
                organization: dataIDOrganization,
                approved: shouldForwardToKSSC,
            },
        };

        const loggedReq = await accessLog(ctx, policyEnforcementDetails);

        if (!loggedReq || !shouldForwardToKSSC) {
            new Event(
                ctx,
                "PolicyEnforcementDeclined",
                policyEnforcementDetails
            ).assignEvent();

            return Shim.success(bufferResponse(false, null));
        }

        if (shouldForwardToKSSC) {
            new Event(
                ctx,
                "PolicyEnforcementAccepted",
                policyEnforcementDetails
            ).assignEvent();

            const KSSCInstance = chaincodeInstances.KSSC.requestData(ctx);
            await KSSCInstance.makeContact([data_id, GID]);

            const [requestData, requestDataErr] = [
                KSSCInstance.response,
                KSSCInstance.error,
            ];

            if (requestDataErr) return Shim.error(requestDataErr.message);

            return Shim.success(bufferResponse(true, requestData));
        }

        return Shim.success(bufferResponse(false, null));
    }
}

// HELPER FUNCTIONS

const getTemporalRolesOfOrgMSP = (verifiedAttributes, organizationMSP) => {
    return verifiedAttributes.TEMPORALROLES[organizationMSP]
        ? verifiedAttributes.TEMPORALROLES[organizationMSP]
        : {};
};

const checkIfActiveEmployee = (TEMPORALROLES, type) => {
    let isOnDuty = false;

    const workingDaysAndHours = accessNestedJSON(
        TEMPORALROLES,
        `${type}_WORK_SHIFT`,
        "DATA"
    );

    if (workingDaysAndHours) {
        let date = new Date();
        let currentDay = weekdays[date.getDay()];
        let currentDayWorkingHours = workingDaysAndHours[currentDay];

        if (currentDayWorkingHours) {
            const currentHour = date.getHours() * 60 + date.getMinutes();

            for (let hours of currentDayWorkingHours) {
                let from = accessNestedJSON(hours, "FROM");
                let to = accessNestedJSON(hours, "TO");

                if (from.match(timeReg) && to.match(timeReg)) {
                    from = from.split(":");
                    to = to.split(":");
                } else {
                    break;
                }

                from = parseInt(from[0], 10) * 60 + parseInt(from[1], 10);
                to = parseInt(to[0], 10) * 60 + parseInt(to[1], 10);
                if (from >= to) {
                    break;
                } else if (from <= currentHour && currentHour <= to) {
                    isOnDuty = true;
                    break;
                }
            }
            return isOnDuty;
        }
    }
    return isOnDuty;
};

const accessNestedJSON = (object, ...args) => {
    return args.reduce((object, level) => object && object[level], object);
};

const accessLog = async (ctx, policy_enfc_details) => {
    const nonce = ctx.stub.getTxID();

    const accessHash = hasher("sha1")
        .update(Buffer.from(JSON.stringify({ nonce, policy_enfc_details })))
        .digest("hex");

    const { policyEnforcementDetails, GID } = policy_enfc_details;

    const recordInstance = Record.createInstance(
        constants.ACSC_LOGS,
        policyEnforcementDetails.data_type,
        GID,
        accessHash,
        policyEnforcementDetails
    );

    try {
        await ctx.recordManager.add(recordInstance);
    } catch (err) {
        return false;
    }

    return recordInstance;
};
