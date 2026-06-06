import type { UserConfig } from "@commitlint/types";

const config: UserConfig = {
  extends: ["@commitlint/config-conventional"],
  rules: {
    "body-empty": [2, "never"],
    "scope-empty": [1, "never"],
    "trailer-exists": [1, "always", "Signed-off-by:"],
  },
};

export default config;
