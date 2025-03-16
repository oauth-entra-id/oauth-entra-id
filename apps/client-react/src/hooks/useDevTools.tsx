import { useEffect, useCallback } from 'react';

export const useDevTools = (isDisabled: boolean) => {
  const disableMouseEvents = useCallback(
    (event: MouseEvent) => {
      if (isDisabled) {
        event.preventDefault();
      }
    },
    [isDisabled],
  );

  const disableShortcuts = useCallback(
    (event: KeyboardEvent) => {
      if (isDisabled) {
        if (
          event.key === 'F12' ||
          (event.ctrlKey && event.shiftKey && (event.key === 'I' || event.key === 'J' || event.key === 'C')) ||
          (event.ctrlKey && event.key === 'U')
        ) {
          event.preventDefault();
        }
      }
    },
    [isDisabled],
  );

  useEffect(() => {
    if (isDisabled) {
      document.addEventListener('contextmenu', disableMouseEvents);
      document.addEventListener('keydown', disableShortcuts);
    }

    return () => {
      document.removeEventListener('contextmenu', disableMouseEvents);
      document.removeEventListener('keydown', disableShortcuts);
    };
  }, [isDisabled, disableMouseEvents, disableShortcuts]);
};
