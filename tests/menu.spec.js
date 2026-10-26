'use strict';

const {test, expect} = require('@playwright/test');
const {buildMenuTemplate} = require('../src/menu');
const {launchApp} = require('./helpers');

const DEV_MENU_LABEL = 'Developer Tools';

/**
 * @param {object[]} template
 * @return {string[]} Every role used anywhere in the template, submenus included.
 */
function collectRoles(template) {
    return template.flatMap(item => [
        ...(item.role ? [item.role] : []),
        ...(item.submenu ? collectRoles(item.submenu) : []),
    ]);
}

test.describe('menu template', () => {
    for (const isMac of [false, true]) {
        const platform = isMac ? 'macOS' : 'Windows/Linux';

        test(`a packaged app on ${platform} has no Developer Tools entries`, () => {
            const template = buildMenuTemplate({isMac, isPackaged: true, appName: 'Recovery Tool'});
            const roles = collectRoles(template);

            expect(template.map(item => item.label)).not.toContain(DEV_MENU_LABEL);
            expect(roles).not.toContain('toggleDevTools');
            expect(roles).not.toContain('reload');
        });

        test(`an unpackaged app on ${platform} keeps the Developer Tools menu`, () => {
            const template = buildMenuTemplate({isMac, isPackaged: false, appName: 'Recovery Tool'});
            const roles = collectRoles(template);

            expect(template.at(-1).label).toBe(DEV_MENU_LABEL);
            expect(roles).toContain('toggleDevTools');
            expect(roles).toContain('reload');
        });
    }

    test('the app name is the first menu on macOS only', () => {
        expect(buildMenuTemplate({isMac: true, isPackaged: true, appName: 'Recovery Tool'})[0])
            .toEqual({label: 'Recovery Tool'});
        expect(buildMenuTemplate({isMac: false, isPackaged: true, appName: 'Recovery Tool'})[0].label)
            .toBe('File');
    });

    test('building the template twice does not accumulate entries', () => {
        const options = {isMac: true, isPackaged: false, appName: 'Recovery Tool'};
        const first = buildMenuTemplate(options);
        const second = buildMenuTemplate(options);

        expect(second).toEqual(first);
        expect(second.filter(item => item.label === DEV_MENU_LABEL)).toHaveLength(1);
    });
});

test.describe('application menu of the running app', () => {
    let electronApp;

    test.afterEach(async () => {
        await electronApp?.close();
    });

    test('an unpackaged run (npm start) shows the Developer Tools menu', async () => {
        ({electronApp} = await launchApp());

        const {isPackaged, labels} = await electronApp.evaluate(({app, Menu}) => ({
            isPackaged: app.isPackaged,
            labels: Menu.getApplicationMenu().items.map(item => item.label),
        }));

        expect(isPackaged).toBe(false);
        expect(labels).toContain(DEV_MENU_LABEL);
    });
});
