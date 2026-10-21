// Colours live only in src/styles/tokens.css; no font size below 12px anywhere.
const config = {
  extends: ["stylelint-config-standard"],
  rules: {
    "color-no-hex": true,
    "color-named": "never",
    "declaration-property-value-disallowed-list": {
      // below 12px, or below 0.75 (r)em
      "font-size": ["/^([0-9]|1[01])(\\.\\d+)?px$/", "/^0?\\.([0-6]\\d*|7([0-4]\\d*)?)r?em$/"],
    },
    "selector-class-pattern": null,
    "custom-property-pattern": null,
    "keyframes-name-pattern": null,
    "no-descending-specificity": null,
    "declaration-block-single-line-max-declarations": null,
    "value-keyword-case": ["lower", { camelCaseSvgKeywords: true, ignoreKeywords: ["BlinkMacSystemFont", "srgb"] }],
  },
  overrides: [
    { files: ["src/styles/tokens.css"], rules: { "color-no-hex": null } },
  ],
};

export default config;
