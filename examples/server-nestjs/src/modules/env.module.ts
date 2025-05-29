import { ConfigModule } from '@nestjs/config';
import { zEnv } from '~/env';

export const EnvModule = ConfigModule.forRoot({
  isGlobal: true,
  validate: (config) => {
    const parsedEnv = zEnv.safeParse(config);
    if (!parsedEnv.success) {
      console.error('❌ Nestjs App environment variables are invalid');
      throw new Error('Invalid environment variables');
    }
    return parsedEnv.data;
  },
});
