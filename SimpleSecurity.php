<?php namespace Ellrion\SimpleSecurity;

class SecurityService
{
    private $rolesList;
    private $currentUser;
    private $cachedRolesList;

    public function __construct($rolesList, $currentUser = null)
    {
        $this->rolesList = $rolesList;
        $this->currentUser = $currentUser;
        $this->flushRolesCache();
    }

    public function isGranted($security, $user = null)
    {
        if (is_null($user)) {
            $accessLevel = $security;
            return $this->checkAccessLevel($accessLevel, $this->currentUser);
        } else {
            $accessLevel = $security;
            $this->flushRolesCache();
            $access = $this->checkAccessLevel($accessLevel, $user);
            $this->flushRolesCache();
            return $access;
        }
    }

    public function addToRolesList($list)
    {
        $this->rolesList = array_merge($this->rolesList, $list);
        $this->flushRolesCache();
    }

    public function getRolesList()
    {
        return $this->cachedRolesList;
    }

    public function flushRolesCache()
    {
        $this->cachedRolesList = $this->rolesList;
    }

    private function checkAccessLevel(&$accessLevel, $user, $prop = array())
    {
        if (is_bool($accessLevel)) {
            return $accessLevel;
        }

        if (empty($accessLevel)) {
            $accessLevel = false;
        } elseif (is_array($accessLevel)) {
            $accessLevel = $this->checkAccessRule($accessLevel, $user, $prop);
        } elseif (is_string($accessLevel)) {
            $accessLevel = $this->checkAccessRole($accessLevel, $user, $prop);
        } elseif (is_callable($accessLevel)) {
            $accessLevel = $this->checkAccessStrategy($accessLevel, $user, $prop);
        } else {
            $accessLevel = true;
        }

        return !empty($accessLevel);
    }

    private function checkAccessRule(&$accessRule, $user, $prop = array())
    {
        if (empty($accessRule) || !is_array($accessRule)) {
            $accessRule = false;
        } else {
            $accessRule = (
                (!isset($accessRule['parent']) || $this->checkAccessLevel($accessRule['parent'], $user, $prop))
                && (!isset($accessRule['allow']) || $this->checkAccessLevel($accessRule['allow'], $user, $prop))
                && (!isset($accessRule['deny']) || !$this->checkAccessLevel($accessRule['deny'], $user, $prop))
            );
        }

        return !empty($accessRule);
    }

    private function checkAccessRole(&$accessRole, $user, $prop = array())
    {
        if (empty($accessRole) || !is_string($accessRole)) {
            $accessRole = false;
        } else {
            if (preg_match('~^([^\*\+\-]*)([\*\+\-]{1})(.*)$~', $accessRole, $matches)) {
                $head = $matches[1];
                $sign = $matches[2];
                $tail = $matches[3];
                if ('+' === $sign) {
                    $accessRole = $this->checkAccessRole($head, $user, $prop)
                        || $this->checkAccessRole($tail, $user, $prop);
                } elseif ('-' === $sign) {
                    $accessRole = $this->checkAccessRole($head, $user, $prop)
                        && !$this->checkAccessRole($tail, $user, $prop);
                } elseif ('*' === $sign) {
                    $accessRole = $this->checkAccessRole($head, $user, $prop)
                        && $this->checkAccessRole($tail, $user, $prop);
                }
            } elseif (strpos($accessRole, ':')) {
                $role_parts = explode(':', $accessRole, 2);
                if (!isset($this->cachedRolesList[$role_parts[0].':'])) {
                    $accessRole = false;
                } else {
                    $this->cachedRolesList[$accessRole] = $this->cachedRolesList[$role_parts[0].':'];
                    $prop = array_merge($prop, array($role_parts[0]=>$role_parts[1]));

                    $accessRole = $accessRole = $this->checkAccessLevel($this->cachedRolesList[$accessRole], $user, $prop);
                }
            } elseif (!isset($this->cachedRolesList[$accessRole])) {
                $accessRole = false;
            } else {
                $accessRole = $this->checkAccessLevel($this->cachedRolesList[$accessRole], $user, $prop);
            }
        }

        return !empty($accessRole);
    }

    private function checkAccessStrategy(&$accessStrategy, $user, $prop = array())
    {
        if (empty($accessStrategy) || !is_callable($accessStrategy)) {
            $accessStrategy = false;
        } else {
            $accessStrategy = $accessStrategy($user, $prop);
        }
        $accessStrategy = $this->checkAccessLevel($accessStrategy, $user, $prop);

        return !empty($accessStrategy);

    }
}