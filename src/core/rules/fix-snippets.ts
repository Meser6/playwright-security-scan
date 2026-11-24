// Fix examples for the rule docs (06-AC-03: nginx, Express and Spring).

export function headerFix(name: string, value: string, springLine: string): string {
  return [
    `Send \`${name}: ${value}\` on every response.`,
    '',
    `- nginx: \`add_header ${name} "${value}" always;\``,
    `- Express: \`app.use((req, res, next) => { res.setHeader('${name}', '${value}'); next(); });\` or the matching \`helmet\` middleware`,
    `- Spring Security: \`${springLine}\``,
  ].join('\n');
}
