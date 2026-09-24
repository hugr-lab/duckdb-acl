import type {SidebarsConfig} from '@docusaurus/plugin-content-docs';

const sidebars: SidebarsConfig = {
  docsSidebar: [
    'index',
    'getting-started',
    'concepts',
    {
      type: 'category',
      label: 'Administering the ACL',
      collapsed: false,
      items: ['management-sql', 'policy-catalog', 'authentication'],
    },
    {
      type: 'category',
      label: 'Serving clients',
      collapsed: false,
      items: ['serving', 'clients/quack', 'clients/dbeaver', 'clients/adbc', 'clients/powerbi-fabric'],
    },
    'security',
    'observability',
    'deployment',
    'development',
  ],
};

export default sidebars;
