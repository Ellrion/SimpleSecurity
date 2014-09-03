<?php
include_once __DIR__ . '/../SimpleSecurity.php';
include_once __DIR__ . '/../OldSimpleSecurity.php';

class SimpleSecurityTest extends PHPUnit_Framework_TestCase
{
    /**
     * @dataProvider provider
     * @group actual
     */
    public function testGranted($rolesList, $securityCondition, $flag)
    {
        $securityService = new Ellrion\SimpleSecurity\SecurityService($rolesList);
        $this->assertEquals($flag, $securityService->isGranted($securityCondition));
    }

    /**
     * @dataProvider provider
     * @group old
     */
    public function testOldGranted($rolesList, $securityCondition, $flag)
    {
        $securityService = new Ellrion\SimpleSecurity\OldSecurityService($rolesList);
        $this->assertEquals($flag, $securityService->isGranted($securityCondition));
    }

    public function provider()
    {
        return array(
            array(['ROLE'], 'ROLE', true)

            , array(['ROLE'=>true], 'ROLE', true)

            , array(['ROLE'=>'all'], 'ROLE', false)
            , array(['all', 'ROLE'=>'all'], 'ROLE', true)
            , array(['all'=>true, 'ROLE'=>'all'], 'ROLE', true)

            , array(['ROLE'=>false], 'ROLE', false)

            , array([], 'ROLE', false)

            , array(['SIMPLE_ROLE'], 'SUPER_ROLE', false)

            , array(['SIMPLE_ROLE'=>true], 'SUPER_ROLE', false)

            , array(['SIMPLE_ROLE'=>false], 'SUPER_ROLE', false)

            , array(['SIMPLE_ROLE'=>1], 'SUPER_ROLE', false)

            , array(['ROLE_1', 'ROLE_2'], 'ROLE_1-ROLE_2', false)
            , array(['ROLE_1', 'ROLE_2'], 'ROLE_1+ROLE_2', true)
            , array(['ROLE_1', 'ROLE_2'], 'ROLE_1*ROLE_2', true)
            , array(['ROLE_1', 'ROLE_2'], 'ROLE_1-ROLE_3', true)
            , array(['ROLE_1', 'ROLE_2'], 'ROLE_1+ROLE_3', true)
            , array(['ROLE_1', 'ROLE_2'], 'ROLE_1*ROLE_3', false)
            , array(['ROLE_1', 'ROLE_2'], 'ROLE_1+ROLE_3-ROLE_2', false)
            , array(['ROLE_1', 'ROLE_2'], 'ROLE_1+ROLE_3-ROLE_20-ROLE_2', false)
            , array(['ROLE_1', 'ROLE_2'], 'ROLE_1-ROLE_2+ROLE_3', false)

        );
    }

}

 