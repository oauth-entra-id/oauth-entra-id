import { cn } from '~/lib/utils';
import { useServerStore } from '~/stores/server-store';
import { SmallMutedText } from './ui/Text';

export function AppInfo() {
  const appInfo = useServerStore((state) => state.appInfo);

  if (!appInfo) return null;

  return (
    <SmallMutedText className="mb-1">
      <span className="font-bold">App Id: </span>
      <span
        className={cn({
          'text-blue-600 dark:text-blue-400': appInfo.currentServiceName === 'blue',
          'text-red-600 dark:text-red-400': appInfo.currentServiceName === 'red',
          'text-yellow-600 dark:text-yellow-400': appInfo.currentServiceName === 'yellow',
        })}>
        {appInfo.currentServiceId}
      </span>
    </SmallMutedText>
  );
}
