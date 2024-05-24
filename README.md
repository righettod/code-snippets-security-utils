💻This project provides different utilities methods to apply processing from a security perspective. These code snippet:
* Can be used, as "foundation", to customize the validation to the app context.
* Were implemented in a way to facilitate adding or removal of validations depending on usage context.
* Were centralized on one class to be able to enhance them across time as well as missing case/bug identification.

📝Code is centralized into the class [SecurityUtils](src/main/java/eu/righettod/SecurityUtils.java) and related uni tests into the class [TestSecurityUtils](src/test/java/eu/righettod/TestSecurityUtils.java).

🔬I uses it, as a sandbox, to create, test and provide remediation code proposals when I perform web assessment or secure code review activities.

💡Java was chosen but idea behind the code proposed can be applied to other language.