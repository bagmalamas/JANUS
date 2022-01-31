// KSSC is placed on each domain blockchain. Is responsible for the partial decryption of data using a system key created on the fly for each user

// MAIN FUNCTION

async requestData(ctx, data_id, GID) {
        const dbcResponse = await forwardToDBCApi(data_id);

        const token = await authenticateWithVault(); // Returns a Token that can be used in order to communicate with the Vault as an authenticated client
        let orgData = jsonParser(dbcResponse);

        if (token.availableToken) {
            if (orgData) {
                if (Array.isArray(orgData)) {
                    let index = 0;
                    for (const elem of orgData) {
                        orgData[index] = await decryptNestedJSON(
                            elem,
                            token,
                            GID
                        );
                        index++;
                    }
                } else {
                    orgData = await decryptNestedJSON(orgData, token, GID);
                }
            }
        }

        return Shim.success(Buffer.from(JSON.stringify(orgData)));
    }

// HELPER FUNCTION

const decryptNestedJSON = async (object, vaultToken, GID) => {
    for (const key in object) {
        if (matchStrings(key, "wrapped_encryption_key"))
            object[key] = await decryptWithVault(vaultToken, object[key], GID);

        if (object[key] !== null && Array.isArray(object[key])) {
            let index = 0;
            for (const elem of object[key]) {
                object[key][index] = await decryptNestedJSON(
                    elem,
                    vaultToken,
                    GID
                );
                index++;
            }
        }

        if (object[key] !== null && typeof object[key] === "object") {
            object[key] = await decryptNestedJSON(object[key], vaultToken, GID);
        }
    }

    return object;
};
