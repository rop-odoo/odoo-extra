# -*- coding: utf-8 -*-
# Part of Odoo. See LICENSE file for full copyright and licensing details.

{
    'name': 'Runbot',
    'category': 'Website',
    'summary': 'Runbot',
    'version': '1.3',
    'description': "Runbot",
    'author': 'Odoo SA',
    'depends': ['website'],
    'external_dependencies': {
        'python': ['matplotlib'],
    },
    'data': [
        'views/runbot_backend.xml',
        'views/runbot_templates.xml',
        'views/res_config_view.xml',
        'security/runbot_security.xml',
        'security/ir.model.access.csv',
        'security/ir.rule.csv',
    ],
    'installable': True,
}
