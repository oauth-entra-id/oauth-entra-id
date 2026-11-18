import { AppInfo } from '~/components/AppInfo';
import { GitHubLink } from '~/components/GitHubLink';
import { LiteTests } from '~/components/LiteTests';
import { ServersDropdown } from '~/components/ServersDropdown';
import { MutedText, Title } from '~/components/ui/Text';

/** The LiteProvider side of the demo: no login, no cookies, no encryption, only plain app tokens. */
export default function Lite() {
  return (
    <div className="flex flex-col items-center justify-center mt-2">
      <div className="flex flex-col items-center justify-center space-y-3 z-10">
        <Title>
          Lite
          <br /> Provider
        </Title>
        <MutedText className="max-w-xs text-center">
          The LiteProvider only verifies plain app tokens and gets B2B tokens, so no login is needed. Switch to
          OAuthProvider above for the full login demo.
        </MutedText>
        <AppInfo />
        <ServersDropdown />
        <LiteTests />
        <MutedText className="max-w-xs text-center">
          To also check that lite refuses a login token, sign in with OAuthProvider in Mobile app mode first, then come
          back here.
        </MutedText>
        <GitHubLink />
      </div>
    </div>
  );
}
