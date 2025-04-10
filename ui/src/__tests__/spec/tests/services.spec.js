/*
 * Copyright The Athenz Authors
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *     http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */

const TEST_NAME_TOOLTIP_LINK_OPENS_NEW_TAB =
    'when clicking help tooltip link, it should open a tab with athenz guide';

describe('services screen tests', () => {
    let currentTest;

    it(TEST_NAME_TOOLTIP_LINK_OPENS_NEW_TAB, async () => {
        currentTest = TEST_NAME_TOOLTIP_LINK_OPENS_NEW_TAB;
        // open browser
        await browser.newUser();
        await browser.url(`/`);
        // select domain
        let domain = 'athenz.dev.functional-test';
        let testDomain = await $(`a*=${domain}`);
        await browser.waitUntil(async () => await testDomain.isClickable());
        await testDomain.click();

        // open Services
        let servicesButton = await $('div*=Services');
        await browser.waitUntil(async () => await servicesButton.isClickable());
        await servicesButton.click();

        // add service
        const serviceName = 'tooltip-link-test-service';
        let addServiceButton = await $('button*=Add Service');
        await addServiceButton.click();
        let serviceNameInput = await $('input[id="service-name"]');
        await serviceNameInput.addValue(serviceName);
        let submitButton = await $('button*=Submit');
        await submitButton.click();

        // navigate to tooltip
        let serviceInstancesButton = await $(
            `.//*[local-name()="svg" and @id="${
                'view-instances-' + serviceName
            }"]`
        );
        await serviceInstancesButton.click();
        // open tooltip
        let instanceHelpTooltipButton = await $(
            `.//*[local-name()="svg" and @id="instances-help-tooltip"]`
        );
        await instanceHelpTooltipButton.click();
        // click athenz guide link
        await browser.pause(1000); // wait a little so that onclick function is assigned to the anchor
        let athenzGuideAnchor = await $('a*=here');
        await athenzGuideAnchor.click();
        await browser.pause(1000); // Just to ensure the new tab opens
        // switch to opened tab
        const windowHandles = await browser.getWindowHandles();
        expect(windowHandles.length).toBeGreaterThan(1);
        await browser.switchToWindow(windowHandles[1]);
        // verify the URL of the new tab
        const url = await browser.getUrl();
        expect(
            url.includes('athenz-guide') || url.includes('yo/service-instances')
        ).toBe(true);
    });

    it('when clicking "Allow" button on a provider without having appropriate authorisation, the error should be displayed to the right of the button', async () => {
        await console.log(`testtesttest inside second test`);
        // open browser
        await browser.newUser();
        await browser.url(`/domain/athenz.dev.test-non-admin/role`);

        // open Services
        let servicesDiv = await $('div*=Services');
        await servicesDiv.click();

        // click Providers
        let providersButton = await $(
            `.//*[local-name()="svg" and @id="provider-test-service-providers"]`
        );
        await providersButton.click();

        // click Azure provider
        let awsProviderAllowButton = await $(
            `td[data-testid="provider-table"]`
        ).$(
            `//td[text()="AWS EC2/EKS/Fargate launches instances for the service"]/following-sibling::td//button`
        );
        await awsProviderAllowButton.click();

        // warning should appear
        let warning = await $(`td[data-testid="provider-table"]`).$(
            `//td[text()="AWS EC2/EKS/Fargate launches instances for the service"]/following-sibling::td//div[text()="Status: 403. Message: Forbidden"]`
        );
        await expect(warning).toHaveText('Status: 403. Message: Forbidden');
    });

    afterEach(async () => {
        if (currentTest === TEST_NAME_TOOLTIP_LINK_OPENS_NEW_TAB) {
            // open browser
            await browser.newUser();
            await browser.url(`/`);
            // select domain
            let domain = 'athenz.dev.functional-test';
            let testDomain = await $(`a*=${domain}`);
            await browser.waitUntil(async () => await testDomain.isClickable());
            await testDomain.click();

            // open Services
            let servicesButton = await $('div*=Services');
            await browser.waitUntil(
                async () => await servicesButton.isClickable()
            );
            await servicesButton.click();

            // delete service created for the test
            let serviceDeleteButton = await $(
                './/*[local-name()="svg" and @id="delete-service-tooltip-link-test-service"]'
            );
            await serviceDeleteButton.click();
            let modalDeleteButton = await $('button*=Delete');
            await modalDeleteButton.click();
        }

        // reset current test
        currentTest = '';
    });
});
