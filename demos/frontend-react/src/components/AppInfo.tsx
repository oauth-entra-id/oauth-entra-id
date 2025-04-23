import { cn } from '~/lib/utils';
import { useServerStore } from '~/stores/serverStore';
import { SmallMutedText } from './ui/Text';

export function AppInfo() {
  const appRegs = useServerStore((state) => state.appRegs);

  if (!appRegs) return null;

  return (
    <SmallMutedText className="mb-1">
      <span className="font-bold">App Id: </span>
      <span
        className={cn({
          'text-blue-600 dark:text-blue-400': appRegs.currentServiceName === 'blue',
          'text-red-600 dark:text-red-400': appRegs.currentServiceName === 'red',
          'text-yellow-600 dark:text-yellow-400': appRegs.currentServiceName === 'yellow',
        })}>
        {appRegs.currentServiceId}
      </span>
    </SmallMutedText>
  );
}
