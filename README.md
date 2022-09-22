Note that in this repository you will find the code for the main functions of Janus system. The full reprodicable demo can been found in CENSUS/Janus repository.

System description

The Janus platform allows stakeholders from different domains that have a shared interest in sensitive data or critical functions, to securely access these, in a manner that is auditable by any stakeholder. Organizations that are stakeholders, may establish policies for the automatic access to their systems and information, based on a requester's characteristics. Such characteristics may be dynamically appointed to a subject by the subject's affiliated stakeholder. Moreover, it is possible for stakeholders of a given domain to establish a domain-wide access policy.

The platform is based on an HMBAC (hierarchical multi-blockchain access control) system, where subjects use ABE (Attribute-Based Encryption) keys to gain access to information. Please note that subject access to the platform requires user authentication through credentials that are not related to the ABE keys, and which can be easily revoked if required. The following diagram provides a high level overview of the platform.

![hmbac-drawing](https://user-images.githubusercontent.com/31564228/191686437-d01cec8e-5687-411e-af13-851fd89a1f1d.png)

The demo environment found in github repository CENSUS/Janus, showcases a deployment made by a fictional governmental organization to coordinate access to patient medical records and deployed medical devices (in hospitals). Stakeholders in this example scenario are grouped into two domains: the hospital organizations (some of which also act as research institutes) and medical device vendors. Each domain operates its own blockchain for domain-applicable requests for information. For example, the hospital domain blockchain serves requests made for patient information, while the device vendor blockchain serves requests regarding the status of medical devices (e.g. firmware availability, fault statistics etc.). To enable stakeholders from different domains to be able to audit any event, an additional blockchain is introduced to track requests regardless of the domain this was initiated upon. This extra blockchain also tracks membership-related information of the aforementioned ecosystem.

![melity-logo-with-text](https://user-images.githubusercontent.com/31564228/191686585-85fc0823-62a2-46c6-9294-7127c04a67d3.png)


The Janus platform is available for use under the 2-clause BSD license (see LICENSE).

    For installation instructions, see setup.md
    For the available requests of the System and clients that you may use to construct a request, please read the demo.md file.
    For the instructions on how to run a Benchmark, please read the benchmark.md file.
    For Frequently Asked Questions, see faq.md

Any mention to actual organization names in the demo data is unintended. Demo data were generated for platform demonstration purposes only. Any such mentions do not imply any endorsement of the platform by these organizations.
