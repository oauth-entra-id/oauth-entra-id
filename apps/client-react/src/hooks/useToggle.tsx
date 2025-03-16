import { useState } from 'react';

export const useToggle = (defaultValue = false) => {
  const [value, setValue] = useState(defaultValue);

  const toggleValue = (booleanValue?: boolean) => {
    setValue((preValue) => booleanValue ?? !preValue);
  };

  return [value, toggleValue] as const;
};
