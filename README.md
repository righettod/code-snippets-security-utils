[![Test](https://github.com/righettod/code-snippets-security-utils/actions/workflows/test.yml/badge.svg?branch=main)](https://github.com/righettod/code-snippets-security-utils/actions/workflows/test.yml) ![MadeWithIntelliJ](https://img.shields.io/static/v1?label=Made%20with&message=Intellij%20IDEA%20Community%20Edition&color=000000&?style=for-the-badge&logo=intellijidea) ![MadeWithMaven](https://img.shields.io/static/v1?label=Made%20with&message=Maven&color=C71A36&?style=for-the-badge&logo=apachemaven) ![AutomatedWith](https://img.shields.io/static/v1?label=Automated%20with&message=GitHub%20Actions&color=blue&?style=for-the-badge&logo=github) ![TargetJDK](https://img.shields.io/static/v1?label=Tested%20with&message=Java%20OpenJDK%2021&color=00AA13&?style=for-the-badge&logo=openjdk)

# Description

> [!NOTE]
> Java was chosen but the ideas behind the proposed code can be applied to other languages.

💻This project provides different utilities methods to apply processing from a security perspective. These code snippet:

* Can be used, as "foundation", to customize the validation to the app context.
* Were implemented in a way to facilitate adding or removal of validations depending on usage context.
* Were centralized into [one class](src/main/java/eu/righettod/SecurityUtils.java) to be able to enhance them across time as well as handle missing case/bug.

🔬I uses it, as a sandbox, to create/test/provide remediation code proposals when I perform web assessment or secure code review activities.

# Disclaimer

> [!CAUTION]
> I do not claim (and will never claim) that the proposed code is 100% effective, these are simply practical tests of ideas regarding security issues I have encountered.

📍The project will not be deployed, as an artefact, into the Maven repository or the GitHub Package repository because the code provided is intended to be tailored to the business and technical context
of the
application.

# Content & conventions

📝Code is centralized into the class [SecurityUtils](src/main/java/eu/righettod/SecurityUtils.java).

🧪Unit tests are centralized into the
class [TestSecurityUtils](src/test/java/eu/righettod/TestSecurityUtils.java).

📖Conventions used:

* One utility methods in **SecurityUtils** class is associated to one unit test methods in **TestSecurityUtils** class: Both with the same name.
* All tests data are stored into the [resources](src/test/resources) folder of the test area.
* Each utility methods have a single goal and is fully documented in terms of usage as well as Internet references used.

# Documentation

The javadoc of the class **SecurityUtils** is exposed [here](https://righettod.github.io/code-snippets-security-utils).

# Usage

👨‍💻The repository can be open directly into [Intellij IDEA](https://www.jetbrains.com/idea/download).

💻Maven command to run all the unit tests:

```shell
$ mvn clean test
[INFO] ------------------------------------------------
[INFO]  T E S T S
[INFO] ------------------------------------------------
[INFO] Running eu.righettod.TestSecurityUtils
[INFO] Tests run: 8, Failures: 0, Errors: 0, Skipped: 0
```




