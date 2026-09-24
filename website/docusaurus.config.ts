import {themes as prismThemes} from 'prism-react-renderer';
import type {Config} from '@docusaurus/types';
import type * as Preset from '@docusaurus/preset-classic';

// Docs for duckdb-acl - role/token-scoped access control for DuckDB. Mirrors the
// tresor, mssql-extension and mssql-ducklake sites and the org site
// (hugr-lab.github.io) so they share look and feel; published by this repo's
// Pages workflow to https://hugr-lab.github.io/duckdb-acl/.

const config: Config = {
  title: 'duckdb-acl',
  tagline: 'Role- and token-scoped access control for DuckDB - virtual catalogs, row-level security, column masking, served over Flight SQL and quack.',
  favicon: 'img/favicon.ico',

  url: 'https://hugr-lab.github.io',
  baseUrl: '/duckdb-acl/',
  trailingSlash: true,

  organizationName: 'hugr-lab',
  projectName: 'duckdb-acl',

  // 'throw', not 'warn': docs-build.yml is the PR gate for website/, and a
  // gate that exits 0 on a broken link does not gate anything.
  onBrokenLinks: 'throw',
  onBrokenAnchors: 'throw',

  i18n: {
    defaultLocale: 'en',
    locales: ['en'],
  },

  presets: [
    [
      'classic',
      {
        docs: {
          sidebarPath: './sidebars.ts',
          // Docs ARE the site: /duckdb-acl/<page>/
          routeBasePath: '/',
          // Versions are made at DEPLOY time from the release tags (pages.yml),
          // so nothing is committed for them; the live docs/ tree publishes as
          // "Next" once a release exists.
          editUrl: 'https://github.com/hugr-lab/duckdb-acl/tree/main/website/',
          showLastUpdateTime: true,
        },
        blog: false,
        theme: {
          customCss: './src/css/custom.css',
        },
      } satisfies Preset.Options,
    ],
  ],

  themes: ['@docusaurus/theme-mermaid'],

  markdown: {
    // the pages are plain Markdown full of `<role>` and `{"caps": ...}`: .md is CommonMark, never MDX
    format: 'detect',
    mermaid: true,
    hooks: {
      onBrokenMarkdownLinks: 'throw',
    },
  },

  themeConfig: {
    metadata: [
      {name: 'keywords', content: 'DuckDB, access control, row-level security, column masking, OIDC, JWT, Arrow Flight SQL, quack, extension'},
      {name: 'description', content: 'DuckDB extension for role- and token-scoped access control: virtual catalogs, row-level security, column masking and function gating, served to real clients over Flight SQL and quack.'},
    ],
    navbar: {
      title: 'duckdb-acl',
      logo: {
        alt: 'Hugr Lab',
        src: 'img/logo-circle.svg',
        href: '/',
      },
      items: [
        {
          type: 'docSidebar',
          sidebarId: 'docsSidebar',
          position: 'left',
          label: 'Docs',
        },
        {
          to: '/management-sql/',
          label: 'SQL reference',
          position: 'left',
        },
        {
          href: 'https://hugr-lab.github.io/',
          label: 'Hugr Lab',
          position: 'right',
        },
        {
          href: 'https://github.com/hugr-lab/duckdb-acl',
          label: 'GitHub',
          position: 'right',
        },
      ],
    },
    colorMode: {
      defaultMode: 'light',
      disableSwitch: true,
      respectPrefersColorScheme: false,
    },
    footer: {
      style: 'dark',
      links: [
        {
          title: 'Docs',
          items: [
            {label: 'Getting started', to: '/getting-started/'},
            {label: 'Concepts', to: '/concepts/'},
            {label: 'Serving clients', to: '/serving/'},
            {label: 'Security model', to: '/security/'},
          ],
        },
        {
          title: 'Community',
          items: [
            {label: 'GitHub', href: 'https://github.com/hugr-lab/duckdb-acl'},
            {label: 'Issues', href: 'https://github.com/hugr-lab/duckdb-acl/issues'},
            {label: 'acl-otel (OpenTelemetry)', href: 'https://hugr-lab.github.io/acl-otel/'},
          ],
        },
        {
          title: 'Hugr Lab',
          items: [
            {label: 'Main site', href: 'https://hugr-lab.github.io/'},
            {label: 'tresor', href: 'https://hugr-lab.github.io/tresor/'},
            {label: 'DuckDB MSSQL Extension', href: 'https://hugr-lab.github.io/mssql-extension/'},
          ],
        },
      ],
      copyright: `Copyright © ${new Date().getFullYear()} Hugr Lab.`,
    },
    prism: {
      theme: prismThemes.github,
      darkTheme: prismThemes.dracula,
      additionalLanguages: ['sql', 'bash', 'json', 'python', 'yaml'],
    },
  } satisfies Preset.ThemeConfig,
};

export default config;
