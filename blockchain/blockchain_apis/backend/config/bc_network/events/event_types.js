module.exports = {
  UpdatedLogData: {
    eventName: "UpdatedLogData",
    eventHumanReadable: "Updated Log Data",
    shouldForward: false,
    shouldAvoid: false,
  },
  ExpiredVotingFound: {
    eventName: "ExpiredVotingFound",
    eventHumanReadable: "Expired Voting Found",
    shouldForward: false,
    shouldAvoid: true,
  },
  VotingInitialized: {
    eventName: "VotingInitialized",
    eventHumanReadable: "Voting Initialized",
    shouldForward: false,
    shouldAvoid: false,
  },
  NewVoteAppended: {
    eventName: "NewVoteAppended",
    eventHumanReadable: "New Vote Appended",
    shouldForward: false,
    shouldAvoid: false,
  },
  ElectionStillInProgress: {
    eventName: "ElectionStillInProgress",
    eventHumanReadable: "Voting Still In Progress",
    shouldForward: false,
    shouldAvoid: true,
  },
  VotingEnded: {
    eventName: "VotingEnded",
    eventHumanReadable: "Voting Ended",
    shouldForward: false,
    shouldAvoid: true,
  },
  RetrieveLogRequestDisapproved: {
    eventName: "RetrieveLogRequestDisapproved",
    eventHumanReadable: "Retrieve Log Request Disapproved",
    shouldForward: false,
    shouldAvoid: true,
  },
  RetrieveLogRequestApproved: {
    eventName: "RetrieveLogRequestApproved",
    eventHumanReadable: "Retrieve Log Request Approved",
    shouldForward: false,
    shouldAvoid: true,
  },
  RequestForwardPBCtoDBC: {
    eventName: "RequestForwardPBCtoDBC",
    eventHumanReadable: "Request Forward PBC to DBC",
    shouldForward: false,
    forwardParameters: {
      from: "PBC",
      to: "DBC",
    },
    shouldAvoid: false,
  },
  RegistrationRequestApproved: {
    eventName: "RegistrationRequestApproved",
    eventHumanReadable: "Registration Request Approved",
    shouldForward: false,
    shouldAvoid: true,
  },
  NewCAAppended: {
    eventName: "NewCAAppended",
    eventHumanReadable: "New CA Appended",
    shouldForward: false,
    shouldAvoid: true,
  },
  RevokedCA: {
    eventName: "RevokedCA",
    eventHumanReadable: "Revoked CA",
    shouldForward: false,
    shouldAvoid: true,
  },
  PolicyEnforcementAccepted: {
    eventName: "PolicyEnforcementAccepted",
    eventHumanReadable: "Policy Enforcement Accepted",
    shouldForward: false,
    shouldAvoid: true,
  },
  PolicyEnforcementDeclined: {
    eventName: "PolicyEnforcementDeclined",
    eventHumanReadable: "Policy Enforcement Declined",
    shouldForward: false,
    shouldAvoid: true,
  },
};
// RETRIEVE_LOG_REQUEST_DISAPPROVED: "RetrieveLogRequestDisapproved",
// RETRIEVE_LOG_REQUEST_APPROVED: "RetrieveLogRequestApproved",
// NEW_VOTE_APPENDED: "NewVoteAppended",
// REQUEST_FORWARD_PBC_TO_DBC: "RequestForwardPBCtoDBC",
// REGISTRATION_REQUEST_APPROVED: "RegistrationRequestApproved",
// NEW_CA_APPENDED: "NewCAAppended",
// REVOKED_CA: "RevokedCA"

