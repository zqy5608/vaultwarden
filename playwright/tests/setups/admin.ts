import { expect, type Browser, Page } from '@playwright/test';
import * as utils from '../../global-utils';

utils.loadEnv();

export async function login(test, page: Page) {
    await test.step(`Admin login`, async () => {
        await page.goto('/admin');
        await page.getByLabel(/^(Admin token|管理令牌)$/).fill(process.env.ADMIN_TOKEN);
        await page.getByRole('button', { name: /^(Enter|登录)$/ }).click();
    });
}

export async function invite(test, page: Page, email: string) {
    await test.step(`Invite user with ${email}`, async () => {
        await page.getByRole('link', { name: /^(Users|用户)$/ }).click();
        await page.getByLabel(/^(Email|邮箱)$/).fill(email);
        await page.getByRole('button', { name: /^(Invite|邀请)$/ }).click();
        await expect(page.getByRole('row', { name: email })).toHaveText(/Invited|已邀请/);
    });
}
