# Description

> [!CAUTION]
> I do not claim (and will never claim) that the proposed code is 100% effective, these are simply practical tests of ideas regarding security issues I have encountered.

> [!NOTE]
> Java was chosen but the ideas behind the proposed code can be applied to other languages.

[![Test](https://github.com/righettod/code-snippets-security-utils/actions/workflows/test.yml/badge.svg?branch=main)](https://github.com/righettod/code-snippets-security-utils/actions/workflows/test.yml)

![MadeWithIntelliJ](https://img.shields.io/static/v1?label=Made%20with&message=Intellij%20IDEA%20Community%20Edition&color=000000&?style=for-the-badge&logo=intellijidea)

![MadeWithMaven](https://img.shields.io/static/v1?label=Made%20with&message=Maven&color=C71A36&?style=for-the-badge&logo=apachemaven)

![AutomatedWith](https://img.shields.io/static/v1?label=Automated%20with&message=GitHub%20Actions&color=blue&?style=for-the-badge&logo=github)

💻This project provides different utilities methods to apply processing from a security perspective. These code snippet:

* Can be used, as "foundation", to customize the validation to the app context.
* Were implemented in a way to facilitate adding or removal of validations depending on usage context.
* Were centralized on one class to be able to enhance them across time as well as missing case/bug identification.

🔬I uses it, as a sandbox, to create, test and provide remediation code proposals when I perform web assessment or secure code review activities.

# Content

📝Code is centralized into the class [SecurityUtils](src/main/java/eu/righettod/SecurityUtils.java).

🧪Unit tests are centralized into the
class [TestSecurityUtils](src/test/java/eu/righettod/TestSecurityUtils.java).

# Usage

👨‍💻The repository can be open directly into [Intellij IDEA](https://www.jetbrains.com/idea/download).



