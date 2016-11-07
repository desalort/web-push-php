<?php

/*
 * This file is part of the WebPush library.
 *
 * (c) Louis Lagrange <lagrange.louis@gmail.com>
 *
 * For the full copyright and license information, please view the LICENSE
 * file that was distributed with this source code.
 */

use Minishlink\WebPush\Utils;
use Minishlink\WebPush\VAPID;

class VAPIDTest extends PHPUnit_Framework_TestCase
{
    public $validAudience = 'https://example.com';
    public $validSubjectMailTo = 'mailto: example@example.com';
    public $validSubjectUrl = 'https://exampe.com/contact';
    public $validPublicKey = 'BF326dtFn8oRwhpL4hoZciv8jdInuXUrL79qGqlYGkz7Fk4jo3iSdglnC9t-DsZM8EDrFeAX8rebK3uN63FUCfE';
    public $validPrivateKey = 'nx9zGwu-qjfAJeWY-toozP_QC2ntjKkVt9JOjcDNMPw';
    public $validExpiration = 1478575110;

    public $expectedJWTHeader = 'eyJ0eXAiOiJKV1QiLCJhbGciOiJFUzI1NiJ9';
    public $expectedJWTPayload = 'eyJhdWQiOiJodHRwczovL2V4YW1wbGUuY29tIiwiZXhwIjoxNDc4NTc1MTEwLCJzdWIiOiJodHRwczovL2V4YW1wZS5jb20vY29udGFjdCJ9';

    public function vapidNoExpirationProvider()
    {
        return array(
            array(
                $this->validAudience,
                $this->validSubjectMailTo,
                $this->validPublicKey,
                $this->validPrivateKey,
                $this->expectedJWTHeader
            ),
            array(
                $this->validAudience,
                $this->validSubjectUrl,
                $this->validPublicKey,
                $this->validPrivateKey,
                $this->expectedJWTHeader
            )
        );

        /**
         * array(
         *    array(
         *     'subject' => 'http://test.com',
         *     'publicKey' => 'BA6jvk34k6YjElHQ6S0oZwmrsqHdCNajxcod6KJnI77Dagikfb--O_kYXcR2eflRz6l3PcI2r8fPCH3BElLQHDk',
         *     'privateKey' => '-3CdhFOqjzixgAbUSa0Zv9zi-dwDVmWO7672aBxSFPQ',
         * ),
         * '1475452165',
         * 'WebPush eyJ0eXAiOiJKV1QiLCJhbGciOiJFUzI1NiJ9.eyJhdWQiOiJodHRwOi8vcHVzaC5jb20iLCJleHAiOjE0NzU0NTIxNjUsInN1YiI6Imh0dHA6Ly90ZXN0LmNvbSJ9.4F3ZKjeru4P9XM20rHPNvGBcr9zxhz8_ViyNfe11_xcuy7A9y7KfEPt6yuNikyW7eT9zYYD5mQZubDGa-5H2cA',
         * 'p256ecdsa=BA6jvk34k6YjElHQ6S0oZwmrsqHdCNajxcod6KJnI77Dagikfb--O_kYXcR2eflRz6l3PcI2r8fPCH3BElLQHDk',
         * )
         */
    }

    public function vapidExpirationProvider()
    {
      return array(
          array(
              $this->validAudience,
              $this->validSubjectMailTo,
              $this->validPublicKey,
              $this->validPrivateKey,
              $this->validExpiration,
              $this->expectedJWTHeader,
              $this->expectedJWTPayload
          ),
      );
    }

    /**
     * @dataProvider vapidNoExpirationProvider
     *
     * @param $audience
     * @param $subject
     * @param $publicKey
     * @param $privateKey
     * @param $expectedJWTHeader
     */
    public function testGetVapidHeaders($audience, $subject, $publicKey, $privateKey, $expectedJWTHeader)
    {
        $vapid = VAPID::validate(array(
          'subject' => $subject,
          'publicKey' => $publicKey,
          'privateKey' => $privateKey
        ));
        $headers = VAPID::getVapidHeaders($audience, $vapid['subject'], $vapid['publicKey'], $vapid['privateKey']);

        $this->assertArrayHasKey('Authorization', $headers);
        $this->assertArrayHasKey('Crypto-Key', $headers);

        $this->assertEquals('p256ecdsa='.$publicKey, $headers['Crypto-Key']);

        $authParts = explode('.', $headers['Authorization']);
        $this->assertEquals('WebPush '.$expectedJWTHeader, $authParts[0]);
    }

    /**
     * @dataProvider vapidExpirationProvider
     * @param  [type] $audience           [description]
     * @param  [type] $subject            [description]
     * @param  [type] $publicKey          [description]
     * @param  [type] $privateKey         [description]
     * @param  [type] $expiration         [description]
     * @param  [type] $expectedJWTHeader  [description]
     * @param  [type] $expectedJWTPayload [description]
     */
    public function testGetVapidHeadersWithExpiration($audience, $subject, $publicKey, $privateKey, $expiration, $expectedJWTHeader, $expectedJWTPayload)
    {
      $vapid = VAPID::validate(array(
        'subject' => $subject,
        'publicKey' => $publicKey,
        'privateKey' => $privateKey
      ));
      $headers = VAPID::getVapidHeaders($audience, $vapid['subject'], $vapid['publicKey'], $vapid['privateKey'], $expiration);

      $this->assertArrayHasKey('Authorization', $headers);
      $this->assertArrayHasKey('Crypto-Key', $headers);

      $this->assertEquals('p256ecdsa='.$publicKey, $headers['Crypto-Key']);

      $authParts = explode('.', $headers['Authorization']);
      $this->assertEquals('WebPush '.$expectedJWTHeader, $authParts[0]);
      $this->assertEquals($expectedJWTPayload, $authParts[1]);
    }
}
