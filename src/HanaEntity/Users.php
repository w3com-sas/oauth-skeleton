<?php

/**
 * This file is auto-generated by Boom.
 */

namespace App\HanaEntity;

use Symfony\Component\Security\Core\User\UserInterface;
use W3com\BoomBundle\Annotation\EntityColumnMeta;
use W3com\BoomBundle\Annotation\EntityMeta;
use W3com\BoomBundle\Annotation\EntitySynchronizedData;
use W3com\BoomBundle\Annotation\SynchronizedData;

/**
 * @EntityMeta(read="sl", write="sl", aliasRead="Users", aliasWrite="Users", synchro=false, isComplex=false)
 */
class Users extends \W3com\BoomBundle\HanaEntity\AbstractEntity implements UserInterface
{
    /**
     * Used in HanaNativeProvider.
     *
     * @var string
     */
    public $companyDb;

	/**
	 * @var int
	 * @EntityColumnMeta(column="InternalKey", description="InternalKey", type="int", synchro=false, quotes=false, isKey=true, isMandatory=true)
	 */
	protected $internalKey;

	/**
	 * @var string
	 * @EntityColumnMeta(column="UserPassword", description="UserPassword", type="string", synchro=false)
	 */
	protected $userPassword;

	/**
	 * @var string
	 * @EntityColumnMeta(column="UserCode", description="UserCode", type="string", synchro=false, isMandatory=true)
	 */
	protected $userCode;

	/**
	 * @var string
	 * @EntityColumnMeta(column="UserName", description="UserName", type="string", synchro=false)
	 */
	protected $userName;

	/**
	 * @var string
	 * @EntityColumnMeta(column="Superuser", description="Superuser", type="string", synchro=false, choices="Non|tNO#Oui|tYES")
	 */
	protected $superuser;

	/**
	 * @var string
	 * @EntityColumnMeta(column="eMail", description="eMail", type="string", synchro=false)
	 */
	protected $eMail;

	/**
	 * @var string
	 * @EntityColumnMeta(column="MobilePhoneNumber", description="MobilePhoneNumber", type="string", synchro=false)
	 */
	protected $mobilePhoneNumber;

	/**
	 * @var string
	 * @EntityColumnMeta(column="Defaults", description="Defaults", type="string", synchro=false)
	 */
	protected $defaults;

	/**
	 * @var string
	 * @EntityColumnMeta(column="FaxNumber", description="FaxNumber", type="string", synchro=false)
	 */
	protected $faxNumber;

	/**
	 * @var int
	 * @EntityColumnMeta(column="Branch", description="Branch", type="int", synchro=false, quotes=false)
	 */
	protected $branch;

	/**
	 * @var int
	 * @EntityColumnMeta(column="Department", description="Department", type="int", synchro=false, quotes=false)
	 */
	protected $department;

	/**
	 * @var string
	 * @EntityColumnMeta(column="Locked", description="Locked", type="string", synchro=false, choices="Non|tNO#Oui|tYES")
	 */
	protected $locked;

	/**
	 * @var string
	 * @EntityColumnMeta(column="Group", description="Group", type="string", synchro=false, choices="ug_Regular|ug_Regular#ug_Deleted|ug_Deleted")
	 */
	protected $group;

	public function getInternalKey()
	{
		return $this->internalKey;
	}


	public function setInternalKey($internalKey)
	{
		return $this->set('internalKey', $internalKey);
	}


	public function getUserPassword()
	{
		return $this->userPassword;
	}


	public function setUserPassword($userPassword)
	{
		return $this->set('userPassword', $userPassword);
	}


	public function getUserCode()
	{
		return $this->userCode;
	}


	public function setUserCode($userCode)
	{
		return $this->set('userCode', $userCode);
	}

    public function getUserIdentifier(): string
    {
        return $this->userName;
    }

	public function getUserName()
	{
		return $this->userName;
	}


	public function setUserName($userName)
	{
		return $this->set('userName', $userName);
	}


	public function getSuperuser()
	{
		return $this->superuser;
	}


	public function setSuperuser($superuser)
	{
		return $this->set('superuser', $superuser);
	}


	public function getEMail()
	{
		return $this->eMail;
	}


	public function setEMail($eMail)
	{
		return $this->set('eMail', $eMail);
	}


	public function getMobilePhoneNumber()
	{
		return $this->mobilePhoneNumber;
	}


	public function setMobilePhoneNumber($mobilePhoneNumber)
	{
		return $this->set('mobilePhoneNumber', $mobilePhoneNumber);
	}


	public function getDefaults()
	{
		return $this->defaults;
	}


	public function setDefaults($defaults)
	{
		return $this->set('defaults', $defaults);
	}


	public function getFaxNumber()
	{
		return $this->faxNumber;
	}


	public function setFaxNumber($faxNumber)
	{
		return $this->set('faxNumber', $faxNumber);
	}


	public function getBranch()
	{
		return $this->branch;
	}


	public function setBranch($branch)
	{
		return $this->set('branch', $branch);
	}


	public function getDepartment()
	{
		return $this->department;
	}


	public function setDepartment($department)
	{
		return $this->set('department', $department);
	}


	public function getLocked()
	{
		return $this->locked;
	}


	public function setLocked($locked)
	{
		return $this->set('locked', $locked);
	}


	public function getGroup()
	{
		return $this->group;
	}


	public function setGroup($group)
	{
		return $this->set('group', $group);
	}

    public function getRoles(): array
    {
        return ['ROLE_NATIVE'];
    }

    public function getPassword()
    {
        return null;
    }

    public function getSalt()
    {
        return null;
    }

    public function eraseCredentials()
    {
    }
}
