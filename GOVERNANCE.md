# Keylime Governance

## Principles

The Keylime community adheres to the following principles:

- Open: Keylime is open source.
- Welcoming and respectful: See [Code of Conduct](CODE_OF_CONDUCT.md).
- Transparent and accessible: Changes to the Keylime organization, Keylime code repositories, and CNCF related activities (e.g. level, involvement, etc) are done in public.
- Merit: Ideas and contributions are accepted according to their technical merit and alignment with
  project objectives, scope, and design principles.


## Project Lead

The Keylime project has a project lead.

A project lead in Keylime is a single person that has a final say in any decision
concerning the Keylime project.

The term of the project lead is one year, with no term limit restriction.

The project lead is elected by Keylime maintainers.

The current project lead is identified in the [MAINTAINERS](MAINTAINERS) file with the string
`project lead` and the term behind the name in a comment at the top of the file.

## Expectations from Maintainers

Every one carries water...

Making a community work requires input/effort from everyone. Maintainers should actively
participate in Pull Request reviews. Maintainers are expected to respond to assigned Pull Requests
in a *reasonable* time frame, either providing insights, or assign the Pull Requests to other
maintainers.

Every Maintainer is listed in the
[CODEOWNERS](https://github.com/keylime/Keylime/blob/master/MAINTAINERS)
file, with their Github handle.

A Maintainer should be active within the CNCF slack #keylime channel

## Becoming a Maintainer

On successful merge of a significant pull request any current maintainer can reach
to the author behind the pull request and ask them if they are willing to become a Keylime
maintainer. The email of the new maintainer invitation should be cc'ed to `keylime@groups.io`
as part of the process.

## Changes in Maintainership

If a Maintainer feels she/he can not fulfill the "Expectations from Maintainers", they are free to
step down.

The Keylime organization will never forcefully remove a current Maintainer, unless a maintainer
fails to meet the principles of Keylime community,
or adhere to the [Code of Conduct](CODE_OF_CONDUCT.md).

## Changes in Project Lead

Changes in project lead or term is initiated by opening a github PR.

Anyone from Keylime community can vote on the PR with either +1 or -1.

Only the following votes are binding:
1) Any maintainer that has been listed in the [MAINTAINERS](MAINTAINERS) file before the PR is opened.
2) Any maintainer from an organization may cast the vote for that organization. However, no organization
should have more binding votes than 1/5 of the total number of maintainers defined in 1).

The PR should only be opened no earlier than 6 weeks before the end of the project lead's term.
The PR should be kept open for no less than 4 weeks. The PR can only be merged after the end of the
last project lead's term, with more +1 than -1 in the binding votes.

When there are conflicting PRs about changes in project lead, the PR with the most binding +1 votes is merged.

The project lead can volunteer to step down.

## Changes in Project Governance

Changes in project governance (GOVERNANCE.md) could be initiated by opening a github PR.
The PR should only be opened no earlier than 6 weeks before the end of the project lead's term.
The PR should be kept open for no less than 4 weeks. The PR can only be merged follow the same
voting process as in [Changes in Project Lead](#Changes_in_Project_Lead)

## Decision making process

Decisions are build on consensus between maintainers.
Proposals and ideas can either be submitted for agreement via a github issue or PR,
or by sending an email to `keylime@groups.io`.

In general, we prefer that technical issues and maintainer membership are amicably worked out between the persons involved.
If a dispute cannot be decided independently, get a third-party maintainer (e.g. a mutual contact with some background on the issue, but not involved in the conflict) to intercede.
If a dispute still cannot be decided, the project lead has the final say to
decide an issue.

Decision making process should be transparent to adhere to the principles of
Keylime project.

All proposals, ideas, and decisions by maintainers or the project lead
should either be part of a github issue or PR, or be sent to `keylime@groups.io`.

## Github Project Administration

The __Keylime__ GitHub project maintainers team reflects the list of Maintainers.

## Other Projects

The Keylime organization is open to receive new sub-projects under its umbrella.
To accept a project into the __Keylime__ organization, it has to meet the
following criteria:

- Must be licensed under the terms of the Apache License v2.0
- Must be related to one or more scopes of the Keylime ecosystem:
  - Security Trust Attestation
  - Keylime project artifacts (website, deployments, CI, etc)
- Must be supported by a Maintainer not associated or affiliated with the author(s) of the sub-projects

The submission process starts as an enhancement on the
[keylime/enhancements](https://github.com/keylime/enhancements) repository with the
required information mentioned above. Once a project is accepted, it's
considered a __CNCF sub-project under the umbrella of Keylime__.

## Keylime and CNCF

Keylime is a CNCF project. As such, Keylime might be involved in CNCF (or other CNCF projects) related
marketing, events, or activities. Any maintainer could help driving the Keylime involvement, as long as
she/he sends email to `keylime@groups.io` (or create a GitHub Pull Request) to call for participation
from other maintainers. The `Call for Participation` should be kept open for no less than a week if time
permits, or a _reasonable_ time frame to allow maintainers to have a chance to volunteer.

## Code of Conduct

The [Keylime Code of Conduct](CODE_OF_CONDUCT.md) is aligned with the CNCF Code of Conduct.

## Credits

Sections of this documents have been borrowed from [CoreDNS](https://github.com/coredns/coredns/blob/master/GOVERNANCE.md).
