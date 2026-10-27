# Release process

```bash
mvn versions:set -DnewVersion=<NEW-VERSION>
```

Commit and tag the version. Then push and create a **GitHub release**.

Finally, publishing to [Maven Central](https://central.sonatype.com/) is **automatically triggered by creating a GitHub release** using GitHub Actions. Artifacts are signed and uploaded through the Central Portal (`central-publishing-maven-plugin`, `deploy` profile).

```bash
mvn versions:set -DnewVersion=<NEW-VERSION With Minor +1 and -SNAPSHOT>
```

Commit and push.

## GitHub Actions Requirements

Publish requires following secrets:

* `CENTRAL_SONATYPE_TOKEN_USERNAME` the Central Portal token username
* `CENTRAL_SONATYPE_TOKEN_PASSWORD` the Central Portal token password
* `GPG_PRIVATE_KEY` the gpg private key used to sign packages
* `GPG_KEY_ID` the id of the gpg key
* `GPG_PASSPHRASE` the gpg private key password

These are provided by the Eclipse Foundation as GitHub organisation's secrets (see the `eclipse-biscuit/.eclipsefdn` Otterdog configuration).
