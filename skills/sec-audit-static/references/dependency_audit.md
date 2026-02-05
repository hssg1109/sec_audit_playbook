# Dependency Audit (Internal Only)

When a user asks for "build-time dependencies" or "imports" in a module, do all of the following and exclude open-source libraries:

1) Extract internal dependencies from the module build file (e.g., `pom.xml` or `build.gradle`).
2) Include internal dependencies inherited via parent/BOM modules (e.g., `pcona-parent`).
3) Scan source code imports for internal package usage (e.g., `com.skplanet.*`).

Report output as a concise list of internal artifacts and internal package namespaces.
