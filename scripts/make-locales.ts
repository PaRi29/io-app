/* eslint-disable no-console */
/**
 * This script converts the translations from the "locales"
 * directory into a typescript file that can be bundled with
 * the app and fed to react-native-i18n.
 *
 * During the conversion, the script selects one locale as the
 * "master" locale (defaults to "en").
 * For the non-master locales the script throws an error if there
 * are missing or extra keys compared to the master locale.
 *
 * The script accepts the following env vars:
 *
 * I18N_IGNORE_LOCALE_ERRORS=1    Ignore locale validation errors.
 * I18N_MASTER_LOCALE=it          Sets a different master locale.
 */

import * as path from "path";
import chalk from "chalk";
import * as fs from "fs-extra";
import * as prettier from "prettier";
import { convertUnknownToError } from "../ts/utils/errors";

interface LocaleDoc {
  locale: string;
  doc: any;
}

interface LocaleDocWithKeys extends LocaleDoc {
  keys: ReadonlyArray<string>;
}

interface LocaleDocWithCheckedKeys extends LocaleDocWithKeys {
  missing: ReadonlyArray<string>;
  extra: ReadonlyArray<string>;
}

const root = path.join(__dirname, "../locales");
// these locales can contains a subset of keys defined in "it"/"en" locales where all translations strings are required
const partialLocales = new Set<string>(["de"]);

/**
 * Reads a locale document.
 *
 * TODO: support including files (e.g. markdown docs)
 */
export async function readLocaleDoc(
  rootPath: string,
  locale: string
): Promise<LocaleDoc> {
  const localePath = path.join(rootPath, locale);
  const filename = path.join(localePath, "index.json");
  const content = await require(filename);

  return {
    locale,
    doc: content
  };
}

/**
 * Extracts all the translation keys from a parsed yaml
 */
export function extractKeys(
  subDoc: any,
  base: string = ""
): ReadonlyArray<string> {
  const baseWithDelimiter = base.length > 0 ? `${base}.` : "";
  const keys = Object.keys(subDoc);
  const terminalKeys = keys
    .filter(k => typeof subDoc[k] === "string")
    .map(k => baseWithDelimiter + k);
  const nonTerminalKeys = keys.filter(k => typeof subDoc[k] === "object");
  const subKeys = nonTerminalKeys.map(k =>
    extractKeys(subDoc[k], baseWithDelimiter + k)
  );
  const flatSubKeys = subKeys.reduce((acc, ks) => acc.concat(ks), []);
  return terminalKeys.concat(flatSubKeys).sort();
}

/**
 * Returns all elements in a that are not in b
 */
function keyDiff(a: ReadonlyArray<string>, b: ReadonlyArray<string>) {
  return a.filter(k => b.indexOf(k) < 0);
}

/**
 * Compares the keys of a locale with the master keys.
 *
 * Returns the keys in the master that are missing in the locale
 * and the extra keys in the locale that are not present in master.
 */
function compareLocaleKeys(
  masterKeys: ReadonlyArray<string>,
  localeKeys: ReadonlyArray<string>
) {
  const missing = keyDiff(masterKeys, localeKeys);
  const extra = keyDiff(localeKeys, masterKeys);
  return {
    missing,
    extra
  };
}

function reportBadLocale(locale: LocaleDocWithCheckedKeys): void {
  console.log("---");
  console.log(
    chalk.redBright(`Locale "${chalk.bold(locale.locale)}" has errors:\n`)
  );
  if (locale.missing.length > 0) {
    console.log(chalk.yellow(`${locale.missing.length} keys are missing:`));
    console.log(locale.missing.join("\n") + "\n");
  }
  if (locale.extra.length > 0) {
    console.log(
      chalk.yellow(
        `${locale.extra.length} keys are not present in the master locale (they must be removed):`
      )
    );
    console.log(locale.extra.join("\n") + "\n");
  }
}

async function emitTsDefinitions(
  locales: ReadonlyArray<LocaleDocWithKeys>,
  emitPath: string
): Promise<void> {
  const localesType = locales.map(l => `"${l.locale}"`).join("|");
  const translationKeys = locales[0].keys.map(k => `  | "${k}"`).join("\n");
  const localesDeclarations = locales
    .map(
      l =>
        `export const locale${l.locale.toUpperCase()} = ${l.locale.toUpperCase()};`
    )
    .join("\n");
  const imports = locales
    .map(
      l => `import ${l.locale.toUpperCase()} from "./${l.locale}/index.json";`
    )
    .join("\n");

  const content = `
/**
 * DO NOT EDIT OR COMMIT THIS FILE!
 *
 * This file has been automatically generated by scripts/make-locales.ts
 */
${imports}

export type Locales = ${localesType};

export type TranslationKeys =
${translationKeys};

${localesDeclarations}
  `;

  return fs.writeFile(
    emitPath,
    prettier.format(content, { parser: "typescript" })
  );
}

// eslint-disable-next-line sonarjs/cognitive-complexity
async function run(rootPath: string): Promise<void> {
  try {
    console.log(chalk.whiteBright("Translations builder"));

    const masterLocale = "it";

    const locales = fs
      .readdirSync(root)
      .filter(d => fs.statSync(path.join(root, d)).isDirectory())
      .sort((a, b) => (a === masterLocale ? -1 : b === masterLocale ? 1 : 0));

    if (locales.indexOf(masterLocale) < 0) {
      throw new Error(`Master locale not found: ${root}/${masterLocale}`);
    }

    console.log("Locales:", chalk.blueBright(locales.join(", ")));
    console.log("Master locale:", chalk.blueBright(masterLocale));
    console.log("Locales path:", chalk.blueBright(rootPath));

    // read the YAML files for all locales
    console.log(chalk.gray("[1/4]"), "Reading translations...");
    const localeDocs = await Promise.all(
      locales.map(async l => await readLocaleDoc(rootPath, l))
    );

    // extract the keys from all locale files
    console.log(chalk.gray("[2/4]"), "Extracting keys...");
    const localeKeys: ReadonlyArray<LocaleDocWithKeys> = localeDocs.map(d => ({
      ...d,
      keys: extractKeys(d.doc)
    }));
    // the master locale is the first one
    const masterKeys = localeKeys[0];
    console.log(
      chalk.greenBright(
        `${chalk.bold(
          String(masterKeys.keys.length)
        )} keys in master locale "${chalk.bold(masterKeys.locale)}"`
      )
    );

    const partialLocalesToString = Array.from(partialLocales)
      .map(l => `"${l}"`)
      .join(",");
    console.log(
      chalk.yellowBright(
        `These locales can be partial defined: ${chalk.whiteBright(
          partialLocalesToString
        )}`
      )
    );

    const otherLocaleKeys = localeKeys.slice(1);
    // compare keys of locales with master keys
    console.log(chalk.gray("[3/4]"), "Comparing keys...");
    const checkedLocaleKeys: ReadonlyArray<LocaleDocWithCheckedKeys> =
      otherLocaleKeys.map(l => ({
        ...l,
        ...compareLocaleKeys(masterKeys.keys, l.keys)
      }));

    // look for locales that have missing or extra keys
    const badLocales = checkedLocaleKeys
      // remove locales for which is allowed to omit translation keys
      .filter(l => !partialLocales.has(l.locale))
      .filter(l => l.missing.length > 0 || l.extra.length > 0);

    if (badLocales.length > 0) {
      badLocales.forEach(reportBadLocale);
      if (!process.env.I18N_IGNORE_LOCALE_ERRORS) {
        throw Error("bad locales detected");
      }
    }

    // look for locales (partial) that have extra keys
    const badLocalesPartial = checkedLocaleKeys
      // include only locales for which is allowed to omit translation keys
      .filter(l => partialLocales.has(l.locale))
      .filter(l => l.extra.length > 0 || l.missing.length > 0);

    const badLocalesPartialExtra = badLocalesPartial.filter(
      l => l.extra.length > 0
    );
    // report if partial locales have extra keys
    if (badLocalesPartialExtra.length > 0) {
      badLocalesPartialExtra.forEach(reportBadLocale);
      throw Error("bad locales detected in partial language");
    }

    // print the partial locale coverage relative to master
    badLocalesPartial.forEach(l => {
      const currentLocale = checkedLocaleKeys.find(
        cl => cl.locale === l.locale
      );
      if (currentLocale) {
        const coveragePerc =
          100 - (currentLocale.missing.length / masterKeys.keys.length) * 100;
        if (coveragePerc !== 0) {
          console.log(
            chalk.yellowBright(`"${currentLocale.locale}" locale`),
            `has a coverage of ${coveragePerc.toFixed(2)}% (${
              masterKeys.keys.length - currentLocale.missing.length
            }/${masterKeys.keys.length} keys)`
          );
        }
      }
    });

    const emitPath = path.join(rootPath, "locales.ts");
    console.log(
      chalk.gray("[4/4]"),
      `Writing locales typescript to [${emitPath}]...`
    );

    await emitTsDefinitions(localeKeys, emitPath);
  } catch (e) {
    console.log(chalk.red(convertUnknownToError(e).message));
  }
}

run(root).then(
  () => console.log("done"),
  () => process.exit(1)
);
