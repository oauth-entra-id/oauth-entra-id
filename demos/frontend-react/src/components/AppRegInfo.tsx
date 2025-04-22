import { cn } from '~/lib/utils';
import { useServerStore } from '~/stores/serverStore';
import { SmallMutedText } from './ui/Text';

export function AppRegInfo() {
  const appRegs = useServerStore((state) => state.appRegs);

  if (!appRegs) return null;

  return (
    <SmallMutedText
      className={cn('mb-1', {
        'text-blue-600 dark:text-blue-400': appRegs.currentColor === 'blue',
        'text-red-600 dark:text-red-400': appRegs.currentColor === 'red',
        'text-yellow-600 dark:text-yellow-400': appRegs.currentColor === 'yellow',
      })}>
      <span className="font-bold">App Id: </span>
      {appRegs.currentAppId}
    </SmallMutedText>
  );
}
