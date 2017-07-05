# -*- coding: utf-8 -*-
# Part of Odoo. See LICENSE file for full copyright and licensing details.

from odoo import api, fields, models


class RunbotConfigSettings(models.TransientModel):
    _name = 'runbot.config.settings'
    _inherit = 'res.config.settings'

    default_workers = fields.Integer('Total Number of Workers')
    default_running_max = fields.Integer('Maximum Number of Running Builds')
    default_timeout = fields.Integer('Default Timeout (in seconds)')
    default_starting_port = fields.Integer('Starting Port for Running Builds')
    default_domain = fields.Char('Runbot Domain')

    @api.model
    def get_values(self):
        ICP = self.env['ir.config_parameter']
        workers = ICP.get_param('runbot.workers', default=6)
        running_max = ICP.get_param('runbot.running_max', default=75)
        timeout = ICP.get_param('runbot.timeout', default=1800)
        starting_port = ICP.get_param('runbot.starting_port', default=2000)
        runbot_domain = ICP.get_param('runbot.domain', default='runbot.odoo.com')
        return {
            'default_workers': int(workers),
            'default_running_max': int(running_max),
            'default_timeout': int(timeout),
            'default_starting_port': int(starting_port),
            'default_domain': runbot_domain,
        }

    @api.multi
    def set_values(self):
        ICP = self.env['ir.config_parameter']
        for config in self:
            ICP.set_param('runbot.workers', config.default_workers)
            ICP.set_param('runbot.running_max', config.default_running_max)
            ICP.set_param('runbot.timeout', config.default_timeout)
            ICP.set_param('runbot.starting_port', config.default_starting_port)
            ICP.set_param('runbot.domain', config.default_domain)
