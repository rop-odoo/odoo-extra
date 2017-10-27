# -*- coding: utf-8 -*-
# Part of Odoo. See LICENSE file for full copyright and licensing details.

import itertools
import hashlib
from collections import OrderedDict

import operator
import werkzeug
from matplotlib.font_manager import FontProperties
from matplotlib.textpath import TextToPath

from odoo import fields, http
from odoo.http import request
from odoo.addons.website.models.website import slug
from odoo.addons.website_sale.controllers.main import QueryURL

def flatten(list_of_lists):
    return list(itertools.chain.from_iterable(list_of_lists))

def uniq_list(l):
    return OrderedDict.fromkeys(l).keys()

def s2human(time):
    """Convert a time in second into an human readable string"""
    for delay, desc in [(86400, 'd'), (3600, 'h'), (60, 'm')]:
        if time >= delay:
            return str(int(time / delay)) + desc
    return str(int(time)) + "s"


class RunbotController(http.Controller):
    @http.route(['/runbot', '/runbot/repo/<model("runbot.repo"):repo>'], type='http', auth="public", website=True)
    def repo(self, repo=None, search='', limit='100', refresh='', **post):
        Branch = request.env['runbot.branch']
        Build = request.env['runbot.build']
        Repo = request.env['runbot.repo']
        count = lambda dom: Build.search_count(dom)

        repos = Repo.search([])
        if not repo and repos:
            repo = repos[0]

        context = {
            'repos': repos,
            'repo': repo,
            'host_stats': [],
            'pending_total': count([('state', '=', 'pending')]),
            'limit': limit,
            'search': search,
            'refresh': refresh,
        }

        build_ids = []
        if repo:
            filters = {key: post.get(key, '1') for key in ['pending', 'testing', 'running', 'done']}
            domain = [('repo_id', '=', repo.id)]
            domain += [('state', '!=', key) for key, value in filters.iteritems() if value == '0']
            if search:
                domain += ['|', '|', ('dest', 'ilike', search), ('subject', 'ilike', search), ('branch_id.branch_name', 'ilike', search)]

            builds = Build.search(domain, limit=int(limit))
            branch_ids, build_by_branch_ids = [], {}

            if builds:
                branch_query = """
                SELECT br.id
                FROM runbot_branch br
                INNER JOIN runbot_build bu ON br.id=bu.branch_id
                WHERE bu.id IN %s
                ORDER BY bu.sequence DESC
                """
                sticky_dom = [('repo_id', '=', repo.id), ('sticky', '=', True)]
                sticky_branch_ids = [] if search else Branch.search(sticky_dom).ids
                request.env.cr.execute(branch_query, (tuple(builds.ids),))
                branch_ids = uniq_list(sticky_branch_ids + [br[0] for br in request.env.cr.fetchall()])

                build_query = """
                    SELECT
                        branch_id,
                        max(case when br_bu.row = 1 then br_bu.build_id end),
                        max(case when br_bu.row = 2 then br_bu.build_id end),
                        max(case when br_bu.row = 3 then br_bu.build_id end),
                        max(case when br_bu.row = 4 then br_bu.build_id end)
                    FROM (
                        SELECT
                            br.id AS branch_id,
                            bu.id AS build_id,
                            row_number() OVER (PARTITION BY branch_id) AS row
                        FROM
                            runbot_branch br INNER JOIN runbot_build bu ON br.id=bu.branch_id
                        WHERE
                            br.id in %s
                        GROUP BY br.id, bu.id
                        ORDER BY br.id, bu.id DESC
                    ) AS br_bu
                    WHERE
                        row <= 4
                    GROUP BY br_bu.branch_id;
                """
                request.env.cr.execute(build_query, (tuple(branch_ids),))
                build_by_branch_ids = {
                    rec[0]: [r for r in rec[1:] if r is not None] for rec in request.env.cr.fetchall()
                }

            branches = Branch.browse(branch_ids)
            build_ids = flatten(build_by_branch_ids.values())
            build_dict = {build.id: build for build in Build.browse(build_ids)}

            def branch_info(branch):
                return {
                    'branch': branch,
                    'builds': [self.build_info(build_dict[build_id]) for build_id in build_by_branch_ids[branch.id]]
                }

            context.update({
                'branches': [branch_info(b) for b in branches],
                'testing': count([('repo_id', '=', repo.id), ('state', '=', 'testing')]),
                'running': count([('repo_id', '=', repo.id), ('state', '=', 'running')]),
                'pending': count([('repo_id', '=', repo.id), ('state', '=', 'pending')]),
                'qu': QueryURL('/runbot/repo/' + slug(repo), search=search, limit=limit, refresh=refresh, **filters),
                'filters': filters,
            })

        # consider host gone if no build in last 100
        build_threshold = max(build_ids or [0]) - 100

        for result in Build.read_group([('id', '>', build_threshold)], ['host'], ['host']):
            if result['host']:
                context['host_stats'].append({
                    'host': result['host'],
                    'testing': count([('state', '=', 'testing'), ('host', '=', result['host'])]),
                    'running': count([('state', '=', 'running'), ('host', '=', result['host'])]),
                })
        return request.render("runbot.repo", context)

    @http.route(['/runbot/hook/<int:repo_id>'], type='http', auth="public", website=True)
    def hook(self, repo_id=None, **post):
        # TODO if repo_id == None parse the json['repository']['ssh_url'] and find the right repo
        repo = request.env['runbot.repo'].sudo().browse([repo_id])
        repo.hook_time = fields.Datetime.now()
        return ""

    @http.route(['/runbot/dashboard'], type='http', auth="public", website=True)
    def dashboard(self, refresh=None):
        cr = request.cr
        RB = request.env['runbot.build']
        repos = request.env['runbot.repo'].search([])   # respect record rules

        cr.execute("""SELECT bu.id
                        FROM runbot_branch br
                        JOIN LATERAL (SELECT *
                                        FROM runbot_build bu
                                       WHERE bu.branch_id = br.id
                                    ORDER BY id DESC
                                       LIMIT 3
                                     ) bu ON (true)
                        JOIN runbot_repo r ON (r.id = br.repo_id)
                       WHERE br.sticky
                         AND br.repo_id in %s
                    ORDER BY r.sequence, r.name, br.branch_name, bu.id DESC
                   """, [tuple(repos._ids)])

        builds = RB.browse(map(operator.itemgetter(0), cr.fetchall()))

        count = RB.search_count
        qctx = {
            'refresh': refresh,
            'host_stats': [],
            'pending_total': count([('state', '=', 'pending')]),
        }

        repos_values = qctx['repo_dict'] = OrderedDict()
        for build in builds:
            repo = build.repo_id
            branch = build.branch_id
            r = repos_values.setdefault(repo.id, {'branches': OrderedDict()})
            if 'name' not in r:
                r.update({
                    'name': repo.name,
                    'base': repo.base,
                    'testing': count([('repo_id', '=', repo.id), ('state', '=', 'testing')]),
                    'running': count([('repo_id', '=', repo.id), ('state', '=', 'running')]),
                    'pending': count([('repo_id', '=', repo.id), ('state', '=', 'pending')]),
                })
            b = r['branches'].setdefault(branch.id, {'name': branch.branch_name, 'builds': list()})
            b['builds'].append(self.build_info(build))

        # consider host gone if no build in last 100
        build_threshold = max(builds.ids or [0]) - 100
        for result in RB.read_group([('id', '>', build_threshold)], ['host'], ['host']):
            if result['host']:
                qctx['host_stats'].append({
                    'host': result['host'],
                    'testing': count([('state', '=', 'testing'), ('host', '=', result['host'])]),
                    'running': count([('state', '=', 'running'), ('host', '=', result['host'])]),
                })

        return request.render("runbot.sticky-dashboard", qctx)

    def build_info(self, build):
        real_build = build.duplicate_id if build.state == 'duplicate' else build
        return {
            'id': build.id,
            'name': build.name,
            'state': real_build.state,
            'result': real_build.result,
            'subject': build.subject,
            'author': build.author,
            'committer': build.committer,
            'dest': build.dest,
            'real_dest': real_build.dest,
            'job_age': s2human(real_build.job_age),
            'job_time': s2human(real_build.job_time),
            'job': real_build.job,
            'domain': real_build.domain,
            'host': real_build.host,
            'port': real_build.port,
            'subject': build.subject,
            'server_match': real_build.server_match,
            'duplicate_of': build.duplicate_id if build.state == 'duplicate' else False,
            'coverage': build.branch_id.coverage,
        }

    @http.route(['/runbot/build/<int:build_id>'], type='http', auth="public", website=True)
    def build(self, build_id, search=None, **post):
        Build = request.env['runbot.build']
        Logging = request.env['ir.logging']

        build = Build.browse([int(build_id)])
        if not build.exists():
            return request.not_found()

        real_build = build.duplicate_id if build.state == 'duplicate' else build

        # other builds
        other_builds = Build.search([('branch_id', '=', build.branch_id.id)])

        domain = [('build_id', '=', real_build.id)]
        #if type:
        #    domain.append(('type', '=', type))
        #if level:
        #    domain.append(('level', '=', level))
        if search:
            domain.append(('message', 'ilike', search))
        loggings = Logging.sudo().search(domain)

        context = {
            'repo': build.repo_id,
            'build': self.build_info(build),
            'br': {'branch': build.branch_id},
            'logs': loggings,
            'other_builds': other_builds
        }
        #context['type'] = type
        #context['level'] = level
        return request.render("runbot.build", context)

    @http.route(['/runbot/build/<int:build_id>/force'], type='http', auth="public", methods=['POST'], csrf=False)
    def build_force(self, build_id, search=None, **post):
        repo_id = request.env['runbot.build'].browse([int(build_id)]).force()
        return werkzeug.utils.redirect('/runbot/repo/%s' % repo_id + ('?search=%s' % search if search else ''))

    @http.route(['/runbot/build/<int:build_id>/kill'], type='http', auth="user", methods=['POST'], csrf=False)
    def build_ask_kill(self, build_id, search=None, **post):
        repo_id = request.env['runbot.build'].browse([int(build_id)])._ask_kill()
        return werkzeug.utils.redirect('/runbot/repo/%s' % repo_id + ('?search=%s' % search if search else ''))

    @http.route([
        '/runbot/badge/<int:repo_id>/<branch>.svg',
        '/runbot/badge/<any(default,flat):theme>/<int:repo_id>/<branch>.svg',
    ], type="http", auth="public", methods=['GET', 'HEAD'])
    def badge(self, repo_id, branch, theme='default'):

        domain = [('repo_id', '=', repo_id),
                  ('branch_id.branch_name', '=', branch),
                  ('branch_id.sticky', '=', True),
                  ('state', 'in', ['testing', 'running', 'done']),
                  ('result', 'not in', ['skipped', 'manually_killed']),
                  ]

        last_update = '__last_update'
        builds = request.env['runbot.build'].sudo().search_read(
            domain, ['state', 'result', 'job_age', last_update],
            order='id desc', limit=1)

        if not builds:
            return request.not_found()

        build = builds[0]
        etag = request.httprequest.headers.get('If-None-Match')
        retag = hashlib.md5(build[last_update]).hexdigest()

        if etag == retag:
            return werkzeug.wrappers.Response(status=304)

        if build['state'] == 'testing':
            state = 'testing'
            cache_factor = 1
        else:
            cache_factor = 2
            if build['result'] == 'ok':
                state = 'success'
            elif build['result'] == 'warn':
                state = 'warning'
            else:
                state = 'failed'

        # from https://github.com/badges/shields/blob/master/colorscheme.json
        color = {
            'testing': "#dfb317",
            'success': "#4c1",
            'failed': "#e05d44",
            'warning': "#fe7d37",
        }[state]

        def text_width(s):
            fp = FontProperties(family='DejaVu Sans', size=11)
            w, h, d = TextToPath().get_text_width_height_descent(s, fp, False)
            return int(w + 1)

        class Text(object):
            __slot__ = ['text', 'color', 'width']
            def __init__(self, text, color):
                self.text = text
                self.color = color
                self.width = text_width(text) + 10

        data = {
            'left': Text(branch, '#555'),
            'right': Text(state, color),
        }
        five_minutes = 5 * 60
        headers = [
            ('Content-Type', 'image/svg+xml'),
            ('Cache-Control', 'max-age=%d' % (five_minutes * cache_factor,)),
            ('ETag', retag),
        ]
        return request.render("runbot.badge_" + theme, data, headers=headers)

    @http.route(['/runbot/b/<branch_name>', '/runbot/<model("runbot.repo"):repo>/<branch_name>'], type='http', auth="public", website=True)
    def fast_launch(self, branch_name=False, repo=False, **post):
        Build = request.env['runbot.build']

        domain = [('branch_id.branch_name', '=', branch_name)]

        if repo:
            domain.extend([('branch_id.repo_id', '=', repo.id)])
            order = "sequence desc"
        else:
            order = 'repo_id ASC, sequence DESC'

        # Take the 10 lasts builds to find at least 1 running... Else no luck
        builds = Build.search(domain, order=order, limit=10)

        if builds:
            last_build = False
            for build in builds:
                if build.state == 'running' or (build.state == 'duplicate' and build.duplicate_id.state == 'running'):
                    last_build = build if build.state == 'running' else build.duplicate_id
                    break

            if not last_build:
                # Find the last build regardless the state to propose a rebuild
                last_build = builds[0]

            if last_build.state != 'running':
                url = "/runbot/build/%s?ask_rebuild=1" % last_build.id
            else:
                url = build.branch_id._get_branch_quickconnect_url(last_build.domain, last_build.dest)[build.branch_id.id]
        else:
            return request.not_found()
        return werkzeug.utils.redirect(url)
