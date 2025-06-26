import { SetMetadata } from '@nestjs/common';

export const IS_APP_KEY = 'isApp';

export const IsApp = () => SetMetadata(IS_APP_KEY, true);
