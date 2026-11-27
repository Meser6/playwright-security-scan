// The authorization tests as catalog entries for the reports and the docs (18-REQ-16, 18-REQ-21):
// manifest and docs like the passive rules. `check` never runs: their findings come from replays.
import type { BuiltInRule } from '../rules/types.ts';
import { AUTHZ_MANIFEST } from './manifest.ts';

const NEVER = (): never[] => [];

const docs: Record<string, BuiltInRule['docs']> = {
  'authz.unauthenticated-access': {
    title: 'Endpoint readable without a session',
    why: 'A GET request that a test made with a session was replayed without any cookie or credential header and got an answer like the one of the logged-in user. Anyone who knows the URL can read the data (broken access control, OWASP A01).',
    fix: [
      'Require an authenticated session on every non-public route and answer 401 (API) or a redirect to the sign-in page (pages) without one.',
      '',
      '- nginx: `auth_request /auth;` in the protected `location` blocks, so the auth service decides before the upstream is called',
      '- Express: an `requireAuth` middleware on the router of the API (`router.use(requireAuth)`) that answers `res.sendStatus(401)` without `req.user`',
      '- Spring Security: `http.authorizeHttpRequests(a -> a.requestMatchers("/public/**").permitAll().anyRequest().authenticated())`',
    ].join('\n'),
    falsePositives:
      'Endpoints that are public on purpose but personalised when logged in (a product page with a wish-list flag): seen without a session in the run, they are recognised as public and not tested. A response that is the same for everyone (settings of the shop) is reported with medium confidence; high only when the answer carries an identifier of the original user.',
  },
  'authz.horizontal': {
    title: "Another user's object readable (IDOR)",
    why: "A request of user A for an object of A (an id in the path or the query) was replayed in the session of user B of the same role, and B got A's object. Users can read each other's data by changing an id (BOLA/IDOR, OWASP A01).",
    fix: [
      'Check on the server that the object belongs to the user of the session (or that the user may see it) before returning it; answer 404 or 403 otherwise. Never rely on ids being hard to guess.',
      '',
      '- nginx: nothing to configure — ownership is application logic; at most `auth_request` to an authorization service that gets the object id',
      '- Express: load the object with the owner in the query (`Invoice.findOne({ id: req.params.id, ownerId: req.user.id })`) and `res.sendStatus(404)` when there is none',
      '- Spring Security: `@PostAuthorize("returnObject.ownerId == authentication.principal.id")` on the service method, or a check in the repository query',
    ].join('\n'),
    falsePositives:
      'Objects shared on purpose between users of a role (a team board): exclude the endpoint with authz.exclude or mark the finding in the baseline. Needs two projects of one role (authz.roles.<project>.role); without them the test is skipped and the coverage says so.',
  },
  'authz.vertical': {
    title: 'Higher-role endpoint readable by a lower role',
    why: 'A request of a role with a higher authz.roles level was replayed in the session of a role with a lower level that never got this endpoint in the tests, and the answer was the same. A lower role can use functions of a higher one (privilege escalation, OWASP A01).',
    fix: [
      'Check the role or permission on the server for every function of a higher role, not only in the menu of the frontend.',
      '',
      '- nginx: `auth_request` to an authorization service that knows the roles, for the admin locations',
      "- Express: a `requireRole('admin')` middleware on the admin router that answers `res.sendStatus(403)`",
      '- Spring Security: `.requestMatchers("/admin/**").hasRole("ADMIN")` or `@PreAuthorize("hasRole(\'ADMIN\')")`',
    ].join('\n'),
    falsePositives:
      'Endpoints both roles may read, but the tests of the lower role never called: reported with medium confidence. Mark them in the baseline as false-positive, or call them in a test of the lower role (then they are not tested vertically).',
  },
};

/** The authorization tests as rules for the report writers; never applied to records. */
export const AUTHZ_RULES: readonly BuiltInRule[] = AUTHZ_MANIFEST.map((manifest) => ({
  id: manifest.id,
  appliesTo: {},
  check: NEVER,
  docs: docs[manifest.id] as BuiltInRule['docs'],
  manifest,
}));
