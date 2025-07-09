import { cn } from '~/lib/utils';
import { useServerStore } from '~/stores/server-store';
import { SmallMutedText } from './ui/Text';

export function AppInfo() {
  const appInfo = useServerStore((state) => state.appInfo);

  if (!appInfo) return null;

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
          {appInfo.currentServiceIds['1'].substring(0, 13)}...
        </span>
        {' , '}
        <span
          className={cn({
            'text-blue-800 dark:text-blue-200': appInfo.currentServiceName === 'blue',
            'text-red-800 dark:text-red-200': appInfo.currentServiceName === 'red',
            'text-yellow-800 dark:text-yellow-200': appInfo.currentServiceName === 'yellow',
          })}>
          {appInfo.currentServiceIds['2'].substring(0, 13)}...
        </span>
      </div>
    </SmallMutedText>
  );
}
