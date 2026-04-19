<!-- This is a checklist of actions required to have a PR reviewed. You should include it and fill it accordingly. (You may only remove it if you check all items and you are a well-known contributor.) -->

**Checklist :**

-   [ ] If you are new to Scapy: I have checked [CONTRIBUTING.md](https://github.com/secdev/scapy/blob/master/CONTRIBUTING.md) (esp. section submitting-pull-requests)
-   [ ] I squashed commits belonging together
-   [ ] I added unit tests or explained why they are not relevant
-   [ ] I executed the regression tests (using `tox`)
-   [ ] If the PR is still not finished, please create a [Draft Pull Request](https://github.blog/2019-02-14-introducing-draft-pull-requests/)
-   [ ] This PR uses (partially) AI-generated code. If so:
    - [ ] I ensured the generated code follows the internal concepts of scapy
    - [ ] This PR has a test coverage > 90%
    - [ ] I reviewed every generated line
    - [ ] If this PR contains more than 500 lines of code (excluding unit tests) I considered splitting this PR.
     - [ ] I considered interoperability tests with existing packages or utilities to ensure conformity of a newly generated protocol

**I understand that failing to mention the use of AI may result in a ban. (We do not forbid it, but you must play fair. Be warned !)**

<!-- brief description what this PR will do, e.g. fixes broken dissection of XXX -->

<!-- if required - short explanation why you fixed something in a way that may look more complicated as it actually is ->>

<!-- if required - outline impacts on other parts of the library -->

fixes #xxx <!-- (add issue number here if appropriate, else remove this line) -->
