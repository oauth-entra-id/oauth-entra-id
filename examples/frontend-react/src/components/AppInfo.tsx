import { cn } from '~/lib/utils';
import { useServerStore } from '~/stores/server-store';
import { useUserStore } from '~/stores/user-store';
import { SmallMutedText } from './ui/Text';

export function AppInfo() {
  const appInfo = useServerStore((state) => state.appInfo);
  const registration = useServerStore((state) => state.registration);
  const user = useUserStore((state) => state.user);

  if (!appInfo) return null;

  // Signed in: show the registration the user actually signed in with. Otherwise: the one selected on the login page.
  const { '1': first, '2': second } = appInfo.currentServiceIds;
  const appId = user ? (user.azureId === second ? second : first) : (appInfo.currentServiceIds[registration] ?? first);

  return (
    <SmallMutedText className="mb-1 flex flex-col items-center">
      <div className="font-bold">App Id: </div>
      <div>
        <span
          className={cn({
            'text-blue-700 dark:text-blue-400': appInfo.currentServiceName === 'blue',
            'text-red-700 dark:text-red-400': appInfo.currentServiceName === 'red',
            'text-yellow-700 dark:text-yellow-400': appInfo.currentServiceName === 'yellow',
          })}>
          {appId.slice(0, 8)}...{appId.slice(-8)}
        </span>
      </div>
    </SmallMutedText>
  );
}
