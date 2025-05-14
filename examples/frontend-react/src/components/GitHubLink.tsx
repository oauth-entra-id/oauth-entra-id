import { GitHub } from './icons/GitHub';

export function GitHubLink() {
  return (
    <a
      className="flex items-center text-xs font-semibold text-muted-foreground hover:text-foreground transition duration-200"
      href="https://github.com/oauth-entra-id/oauth-entra-id"
      target="_blank"
      rel="noopener noreferrer">
      <GitHub className="size-3 mx-1" /> GitHub
    </a>
  );
}
