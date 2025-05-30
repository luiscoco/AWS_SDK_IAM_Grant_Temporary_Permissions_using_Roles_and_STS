# Granting Temporary AWS Permissions with IAM Roles and STS

**IMPORTRANT NOTE**: visit the following sites to get the latest information about AWS SDK for .NET

https://docs.aws.amazon.com/sdk-for-net/v4/developer-guide/csharp_code_examples.html

https://github.com/awsdocs/aws-doc-sdk-examples/tree/main/dotnetv4

https://github.com/aws/aws-sdk-net/


In this hands-on guide, I walk through how to grant temporary permissions in AWS using **IAM Roles** and the Security Token Service (**STS**) to assume a role, all implemented in a **.NET 10** console application using **AWS SDK for .NET version 4**.

This example application does the following:

a) **Creates a user** with no permissions

b) **Create an Access Key** for the new user

c) **Creates a role and policy** that grant s3:ListAllMyBuckets permission

d) Grants the **user** permission to **assume the role**

e) **Creates an S3 client** object as the user and tries to **list buckets** (this **will FAIL!!!**)

f) **Gets temporary credentials** by assuming the role

g) **Creates a new S3** client object **with the temporary credentials** and **lists the buckets** (this **will SUCCEED**)

h) **Delete** all the **resources**

For more detailed information about this post visit the official AWS SDK for .NET website:

https://docs.aws.amazon.com/sdk-for-net/v4/developer-guide/csharp_iam_code_examples.html

## 1. Prerrequisites

### 1.1. Download and Install .NET 10

![image](https://github.com/user-attachments/assets/a2cf025f-ef65-43ec-97b1-ca834059f847)

### 1.2. Install Visual Studio 2022 v17.4(Preview) Community Edition

![image](https://github.com/user-attachments/assets/e585e65e-af7a-4ecb-abd2-aa35aa533c32)

### 1.3. Install and Configure AWS CLI

We download and install **AWS CLI**

https://docs.aws.amazon.com/cli/latest/userguide/getting-started-install.html

![image](https://github.com/user-attachments/assets/21ca0743-27c0-4756-9021-3e7cc71f352f)

We login in **AWS Console** and create a **AWS Access Key ID** and **AWS Secret Access Key**

![image](https://github.com/user-attachments/assets/5497a327-2edd-4e20-9392-98d7ae40fb0e)

![image](https://github.com/user-attachments/assets/04515e95-d60d-461f-ae45-7d26d517ca3a)

![image](https://github.com/user-attachments/assets/42130ad9-952d-4364-81fa-0e2c77128939)

![image](https://github.com/user-attachments/assets/0ffbdde6-add7-4a65-affb-015e6d7688a2)

![image](https://github.com/user-attachments/assets/a58bb7b4-2bc0-479a-a4c8-bf1d0d40800e)

We execute the following command to configure AWS CLI

```
aws configure
```

We input the **AWS Access Key ID** and **AWS Secret Access Key** already generated in the AWS Console

![image](https://github.com/user-attachments/assets/cd848db4-b61a-4449-844f-54e36bb7993a)

## 2. Create a C# Console application with .NET 10 and Visual Studio v17.4 Community Edition

We run Visual Studio 2022 v17.4 and we create a new project

![image](https://github.com/user-attachments/assets/326e2552-1024-4304-a181-2daf58882f1a)

We select the C# Console project template

![image](https://github.com/user-attachments/assets/da2fbbe0-cc58-4c95-8493-b97411d80bb9)

We input the project name and location

![image](https://github.com/user-attachments/assets/5a6ccd47-ae19-483c-a6d8-25ffd4de9868)

We select the project .NET 10 framework and we finally create the new solution

![image](https://github.com/user-attachments/assets/c601d7dd-f318-439c-b987-af33f72bbfdc)

## 3. Add Nuget Packages

These packages work together to create a modern .NET console app that:

Uses AWS SDK v4 to manage IAM, S3, and STS services

Leverages .NET Hosting, DI, and Configuration to follow clean architecture and scalable patterns

**AWS Packages (AWSSDK 4.0.0-preview.11)**: These are part of the AWS SDK for .NET version 4 (preview)

**AWSSDK.Extensions.NETCore.Setup**: Enables integration with .NET dependency injection (DI) and configuration

Lets you register AWS services (e.g., S3, IAM) using services.AddAWSService<>()

**AWSSDK.IdentityManagement**: AWS SDK for interacting with IAM (Identity and Access Management)

Provides APIs to:

a) Create/delete users, roles, and groups

b) Attach policies

c) Manage permissions

**AWSSDK.S3**: AWS SDK for Amazon S3 (Simple Storage Service)

Allows creating, listing, deleting buckets and objects

**AWSSDK.SecurityToken**: AWS SDK for AWS STS (Security Token Service)

Used for:

a) Assuming roles

b) Generating temporary credentials

c) Secure cross-account access

**Microsoft Extensions (10.0.0-preview.2)**: These are from the .NET 8/10 preview ecosystem and are part of the .NET Hosting & Configuration model

**Microsoft.Extensions.Configuration**: Enables structured app configuration (e.g., appsettings.json, environment variables, etc.)

Used to read configuration values like IAM user names, role names, etc

**Microsoft.Extensions.Hosting**: Provides the generic host builder used in .NET Core apps

Handles:

a) App lifecycle

b) Dependency injection

c) Logging

d) Background services

![image](https://github.com/user-attachments/assets/bd116b2e-a14b-41cc-8652-c318a4b63169)

## 4. Create the solution files structure

![image](https://github.com/user-attachments/assets/556b6758-6c50-4d44-af1a-c96f272d8194)

## 5. Adding the settings.json file

```json
{
  "UserName": "iam-test-user",
  "S3PolicyName": "s3-list-buckets-policy",
  "RoleName": "test-temporary-role",
  "AssumePolicyName": "test-trust-user",
  "BucketName": "my-test-bucket",
  "GroupName": "test-group"
}
```

## 6. Input the IAMWrapper.cs code

The **IAMWrapper class** is a C# wrapper around the AWS Identity and Access Management (**IAM**) service using the AWS SDK for .NET

It provides convenient, high-level async methods for managing IAM resources like users, roles, policies, and access keys

**Why Use IAMWrapper class?**

a) It abstracts repetitive IAM API code into clean, reusable methods.

b) Makes IAM management more developer-friendly and testable.

c) Useful for automation scripts, CI/CD pipelines, and admin tools.

**Key Operations Implemented (Async Methods)**:

a) **Create**: CreateUserAsync, CreateRoleAsync, CreatePolicyAsync, CreateAccessKeyAsync, CreateServiceLinkedRoleAsync

b) **Get Info**: GetUserAsync, GetRoleAsync, GetPolicyAsync, GetAccountPasswordPolicyAsync

c) **Attach/Detach Policies**: AttachRolePolicyAsync, DetachRolePolicyAsync

d) **Put (Inline) Policies**: PutRolePolicyAsync, PutUserPolicyAsync

e) **Delete Operations**: IAM users, roles, policies, access keys, inline policies.

f) **List Operations (with pagination support)**: List of users, roles, policies, groups, SAML providers, etc.

g) **WaitUntilAccessKeyIsReady**: Polls until a newly created access key is available for use.

```csharp
// Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0

using Amazon.IdentityManagement.Model;
using System.Net;

namespace IAMActions;

public class IAMWrapper
{
    private readonly IAmazonIdentityManagementService _IAMService;

    /// <summary>
    /// Constructor for the IAMWrapper class.
    /// </summary>
    /// <param name="IAMService">An IAM client object.</param>
    public IAMWrapper(IAmazonIdentityManagementService IAMService)
    {
        _IAMService = IAMService;
    }

    /// <summary>
    /// Attach an IAM policy to a role.
    /// </summary>
    /// <param name="policyArn">The policy to attach.</param>
    /// <param name="roleName">The role that the policy will be attached to.</param>
    /// <returns>A Boolean value indicating the success of the action.</returns>
    public async Task<bool> AttachRolePolicyAsync(string policyArn, string roleName)
    {
        var response = await _IAMService.AttachRolePolicyAsync(new AttachRolePolicyRequest
        {
            PolicyArn = policyArn,
            RoleName = roleName,
        });

        return response.HttpStatusCode == System.Net.HttpStatusCode.OK;
    }

    /// <summary>
    /// Create an IAM access key for a user.
    /// </summary>
    /// <param name="userName">The username for which to create the IAM access
    /// key.</param>
    /// <returns>The AccessKey.</returns>
    public async Task<AccessKey> CreateAccessKeyAsync(string userName)
    {
        var response = await _IAMService.CreateAccessKeyAsync(new CreateAccessKeyRequest
        {
            UserName = userName,
        });

        return response.AccessKey;

    }

    /// <summary>
    /// Create an IAM policy.
    /// </summary>
    /// <param name="policyName">The name to give the new IAM policy.</param>
    /// <param name="policyDocument">The policy document for the new policy.</param>
    /// <returns>The new IAM policy object.</returns>
    public async Task<ManagedPolicy> CreatePolicyAsync(string policyName, string policyDocument)
    {
        var response = await _IAMService.CreatePolicyAsync(new CreatePolicyRequest
        {
            PolicyDocument = policyDocument,
            PolicyName = policyName,
        });

        return response.Policy;
    }

    /// <summary>
    /// Create a new IAM role.
    /// </summary>
    /// <param name="roleName">The name of the IAM role.</param>
    /// <param name="rolePolicyDocument">The name of the IAM policy document
    /// for the new role.</param>
    /// <returns>The Amazon Resource Name (ARN) of the role.</returns>
    public async Task<string> CreateRoleAsync(string roleName, string rolePolicyDocument)
    {
        var request = new CreateRoleRequest
        {
            RoleName = roleName,
            AssumeRolePolicyDocument = rolePolicyDocument,
        };

        var response = await _IAMService.CreateRoleAsync(request);
        return response.Role.Arn;
    }

    /// <summary>
    /// Create an IAM service-linked role.
    /// </summary>
    /// <param name="serviceName">The name of the AWS Service.</param>
    /// <param name="description">A description of the IAM service-linked role.</param>
    /// <returns>The IAM role that was created.</returns>
    public async Task<Role> CreateServiceLinkedRoleAsync(string serviceName, string description)
    {
        var request = new CreateServiceLinkedRoleRequest
        {
            AWSServiceName = serviceName,
            Description = description
        };

        var response = await _IAMService.CreateServiceLinkedRoleAsync(request);
        return response.Role;
    }

    /// <summary>
    /// Create an IAM user.
    /// </summary>
    /// <param name="userName">The username for the new IAM user.</param>
    /// <returns>The IAM user that was created.</returns>
    public async Task<User> CreateUserAsync(string userName)
    {
        var response = await _IAMService.CreateUserAsync(new CreateUserRequest { UserName = userName });
        return response.User;
    }

    /// <summary>
    /// Delete an IAM user's access key.
    /// </summary>
    /// <param name="accessKeyId">The Id for the IAM access key.</param>
    /// <param name="userName">The username of the user that owns the IAM
    /// access key.</param>
    /// <returns>A Boolean value indicating the success of the action.</returns>
    public async Task<bool> DeleteAccessKeyAsync(string accessKeyId, string userName)
    {
        var response = await _IAMService.DeleteAccessKeyAsync(new DeleteAccessKeyRequest
        {
            AccessKeyId = accessKeyId,
            UserName = userName,
        });

        return response.HttpStatusCode == System.Net.HttpStatusCode.OK;
    }

    /// <summary>
    /// Delete an IAM policy.
    /// </summary>
    /// <param name="policyArn">The Amazon Resource Name (ARN) of the policy to
    /// delete.</param>
    /// <returns>A Boolean value indicating the success of the action.</returns>
    public async Task<bool> DeletePolicyAsync(string policyArn)
    {
        var response = await _IAMService.DeletePolicyAsync(new DeletePolicyRequest { PolicyArn = policyArn });
        return response.HttpStatusCode == System.Net.HttpStatusCode.OK;
    }

    /// <summary>
    /// Delete an IAM role.
    /// </summary>
    /// <param name="roleName">The name of the IAM role to delete.</param>
    /// <returns>A Boolean value indicating the success of the action.</returns>
    public async Task<bool> DeleteRoleAsync(string roleName)
    {
        var response = await _IAMService.DeleteRoleAsync(new DeleteRoleRequest { RoleName = roleName });
        return response.HttpStatusCode == System.Net.HttpStatusCode.OK;
    }

    /// <summary>
    /// Delete an IAM role policy.
    /// </summary>
    /// <param name="roleName">The name of the IAM role.</param>
    /// <param name="policyName">The name of the IAM role policy to delete.</param>
    /// <returns>A Boolean value indicating the success of the action.</returns>
    public async Task<bool> DeleteRolePolicyAsync(string roleName, string policyName)
    {
        var response = await _IAMService.DeleteRolePolicyAsync(new DeleteRolePolicyRequest
        {
            PolicyName = policyName,
            RoleName = roleName,
        });

        return response.HttpStatusCode == System.Net.HttpStatusCode.OK;
    }

    /// <summary>
    /// Delete an IAM user.
    /// </summary>
    /// <param name="userName">The username of the IAM user to delete.</param>
    /// <returns>A Boolean value indicating the success of the action.</returns>
    public async Task<bool> DeleteUserAsync(string userName)
    {
        var response = await _IAMService.DeleteUserAsync(new DeleteUserRequest { UserName = userName });

        return response.HttpStatusCode == System.Net.HttpStatusCode.OK;
    }

    /// <summary>
    /// Delete an IAM user policy.
    /// </summary>
    /// <param name="policyName">The name of the IAM policy to delete.</param>
    /// <param name="userName">The username of the IAM user.</param>
    /// <returns>A Boolean value indicating the success of the action.</returns>
    public async Task<bool> DeleteUserPolicyAsync(string policyName, string userName)
    {
        var response = await _IAMService.DeleteUserPolicyAsync(new DeleteUserPolicyRequest { PolicyName = policyName, UserName = userName });

        return response.HttpStatusCode == System.Net.HttpStatusCode.OK;
    }

    /// <summary>
    /// Detach an IAM policy from an IAM role.
    /// </summary>
    /// <param name="policyArn">The Amazon Resource Name (ARN) of the IAM policy.</param>
    /// <param name="roleName">The name of the IAM role.</param>
    /// <returns>A Boolean value indicating the success of the action.</returns>
    public async Task<bool> DetachRolePolicyAsync(string policyArn, string roleName)
    {
        var response = await _IAMService.DetachRolePolicyAsync(new DetachRolePolicyRequest
        {
            PolicyArn = policyArn,
            RoleName = roleName,
        });

        return response.HttpStatusCode == System.Net.HttpStatusCode.OK;
    }

    /// <summary>
    /// Gets the IAM password policy for an AWS account.
    /// </summary>
    /// <returns>The PasswordPolicy for the AWS account.</returns>
    public async Task<PasswordPolicy> GetAccountPasswordPolicyAsync()
    {
        var response = await _IAMService.GetAccountPasswordPolicyAsync(new GetAccountPasswordPolicyRequest());
        return response.PasswordPolicy;
    }

    /// <summary>
    /// Get information about an IAM policy.
    /// </summary>
    /// <param name="policyArn">The IAM policy to retrieve information for.</param>
    /// <returns>The IAM policy.</returns>
    public async Task<ManagedPolicy> GetPolicyAsync(string policyArn)
    {

        var response = await _IAMService.GetPolicyAsync(new GetPolicyRequest { PolicyArn = policyArn });
        return response.Policy;
    }

    /// <summary>
    /// Get information about an IAM role.
    /// </summary>
    /// <param name="roleName">The name of the IAM role to retrieve information
    /// for.</param>
    /// <returns>The IAM role that was retrieved.</returns>
    public async Task<Role> GetRoleAsync(string roleName)
    {
        var response = await _IAMService.GetRoleAsync(new GetRoleRequest
        {
            RoleName = roleName,
        });

        return response.Role;
    }

    /// <summary>
    /// Get information about an IAM user.
    /// </summary>
    /// <param name="userName">The username of the user.</param>
    /// <returns>An IAM user object.</returns>
    public async Task<User> GetUserAsync(string userName)
    {
        var response = await _IAMService.GetUserAsync(new GetUserRequest { UserName = userName });
        return response.User;
    }

    /// <summary>
    /// List the IAM role policies that are attached to an IAM role.
    /// </summary>
    /// <param name="roleName">The IAM role to list IAM policies for.</param>
    /// <returns>A list of the IAM policies attached to the IAM role.</returns>
    public async Task<List<AttachedPolicyType>> ListAttachedRolePoliciesAsync(string roleName)
    {
        var attachedPolicies = new List<AttachedPolicyType>();
        var attachedRolePoliciesPaginator = _IAMService.Paginators.ListAttachedRolePolicies(new ListAttachedRolePoliciesRequest { RoleName = roleName });

        await foreach (var response in attachedRolePoliciesPaginator.Responses)
        {
            attachedPolicies.AddRange(response.AttachedPolicies);
        }

        return attachedPolicies;
    }

    /// <summary>
    /// List IAM groups.
    /// </summary>
    /// <returns>A list of IAM groups.</returns>
    public async Task<List<Group>> ListGroupsAsync()
    {
        var groupsPaginator = _IAMService.Paginators.ListGroups(new ListGroupsRequest());
        var groups = new List<Group>();

        await foreach (var response in groupsPaginator.Responses)
        {
            groups.AddRange(response.Groups);
        }

        return groups;
    }

    /// <summary>
    /// List IAM policies.
    /// </summary>
    /// <returns>A list of the IAM policies.</returns>
    public async Task<List<ManagedPolicy>> ListPoliciesAsync()
    {
        var listPoliciesPaginator = _IAMService.Paginators.ListPolicies(new ListPoliciesRequest());
        var policies = new List<ManagedPolicy>();

        await foreach (var response in listPoliciesPaginator.Responses)
        {
            policies.AddRange(response.Policies);
        }

        return policies;
    }

    /// <summary>
    /// List IAM role policies.
    /// </summary>
    /// <param name="roleName">The IAM role for which to list IAM policies.</param>
    /// <returns>A list of IAM policy names.</returns>
    public async Task<List<string>> ListRolePoliciesAsync(string roleName)
    {
        var listRolePoliciesPaginator = _IAMService.Paginators.ListRolePolicies(new ListRolePoliciesRequest { RoleName = roleName });
        var policyNames = new List<string>();

        await foreach (var response in listRolePoliciesPaginator.Responses)
        {
            policyNames.AddRange(response.PolicyNames);
        }

        return policyNames;
    }

    /// <summary>
    /// List IAM roles.
    /// </summary>
    /// <returns>A list of IAM roles.</returns>
    public async Task<List<Role>> ListRolesAsync()
    {
        var listRolesPaginator = _IAMService.Paginators.ListRoles(new ListRolesRequest());
        var roles = new List<Role>();

        await foreach (var response in listRolesPaginator.Responses)
        {
            roles.AddRange(response.Roles);
        }

        return roles;
    }

    /// <summary>
    /// List SAML authentication providers.
    /// </summary>
    /// <returns>A list of SAML providers.</returns>
    public async Task<List<SAMLProviderListEntry>> ListSAMLProvidersAsync()
    {
        var response = await _IAMService.ListSAMLProvidersAsync(new ListSAMLProvidersRequest());
        return response.SAMLProviderList;
    }

    /// <summary>
    /// List IAM users.
    /// </summary>
    /// <returns>A list of IAM users.</returns>
    public async Task<List<User>> ListUsersAsync()
    {
        var listUsersPaginator = _IAMService.Paginators.ListUsers(new ListUsersRequest());
        var users = new List<User>();

        await foreach (var response in listUsersPaginator.Responses)
        {
            users.AddRange(response.Users);
        }

        return users;
    }

    /// <summary>
    /// Update the inline policy document embedded in a role.
    /// </summary>
    /// <param name="policyName">The name of the policy to embed.</param>
    /// <param name="roleName">The name of the role to update.</param>
    /// <param name="policyDocument">The policy document that defines the role.</param>
    /// <returns>A Boolean value indicating the success of the action.</returns>
    public async Task<bool> PutRolePolicyAsync(string policyName, string roleName, string policyDocument)
    {
        var request = new PutRolePolicyRequest
        {
            PolicyName = policyName,
            RoleName = roleName,
            PolicyDocument = policyDocument
        };

        var response = await _IAMService.PutRolePolicyAsync(request);
        return response.HttpStatusCode == HttpStatusCode.OK;
    }

    /// <summary>
    /// Add or update an inline policy document that is embedded in an IAM user.
    /// </summary>
    /// <param name="userName">The name of the IAM user.</param>
    /// <param name="policyName">The name of the IAM policy.</param>
    /// <param name="policyDocument">The policy document defining the IAM policy.</param>
    /// <returns>A Boolean value indicating the success of the action.</returns>
    public async Task<bool> PutUserPolicyAsync(string userName, string policyName, string policyDocument)
    {
        var request = new PutUserPolicyRequest
        {
            UserName = userName,
            PolicyName = policyName,
            PolicyDocument = policyDocument
        };

        var response = await _IAMService.PutUserPolicyAsync(request);
        return response.HttpStatusCode == System.Net.HttpStatusCode.OK;
    }

    /// <summary>
    /// Wait for a new access key to be ready to use.
    /// </summary>
    /// <param name="accessKeyId">The Id of the access key.</param>
    /// <returns>A boolean value indicating the success of the action.</returns>
    public async Task<bool> WaitUntilAccessKeyIsReady(string accessKeyId)
    {
        var keyReady = false;

        do
        {
            try
            {
                var response = await _IAMService.GetAccessKeyLastUsedAsync(
                    new GetAccessKeyLastUsedRequest { AccessKeyId = accessKeyId });
                if (response.UserName is not null)
                {
                    keyReady = true;
                }
            }
            catch (NoSuchEntityException)
            {
                keyReady = false;
            }
        } while (!keyReady);

        return keyReady;
    }
}
```


## 7. Input the S3Wrapper.cs code

The S3Wrapper class provides a simplified way to interact with Amazon S3 and AWS STS (Security Token Service) for common operations, mainly used in IAM (Identity and Access Management) learning or scenario-based testing

This class is likely used in IAM training scenarios, especially to demonstrate how permissions affect access to S3 buckets, and how role-assumption works in practice

**Key Responsibilities**
a) **Constructor**: Accepts two AWS client objects:

**IAmazonS3**: to perform S3 operations

**IAmazonSecurityTokenService**: to assume IAM roles

b) **AssumeS3RoleAsync()**: Uses AWS STS to assume a specific IAM role, returning temporary credentials

c) **PutBucketAsync()**: Creates a new S3 bucket with the given name

d) **DeleteBucketAsync()**: Deletes an existing S3 bucket

e) **ListMyBucketsAsync()**: Lists all S3 buckets owned by the account (or assumed role). Handles S3-specific exceptions

f) **UpdateClients()**: Allows replacing the internal S3 and STS clients, useful for updating permissions dynamically during a scenario

```csharp
// Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0

namespace IamScenariosCommon;

using Amazon.S3;
using Amazon.S3.Model;
using Amazon.SecurityToken.Model;
using System.Net;

/// <summary>
/// A class to perform Amazon Simple Storage Service (Amazon S3) actions for
/// the IAM Basics scenario.
/// </summary>
public class S3Wrapper
{
    private IAmazonS3 _s3Service;
    private IAmazonSecurityTokenService _stsService;

    /// <summary>
    /// Constructor for the S3Wrapper class.
    /// </summary>
    /// <param name="s3Service">An Amazon S3 client object.</param>
    /// <param name="stsService">An AWS Security Token Service (AWS STS)
    /// client object.</param>
    public S3Wrapper(IAmazonS3 s3Service, IAmazonSecurityTokenService stsService)
    {
        _s3Service = s3Service;
        _stsService = stsService;
    }

    /// <summary>
    /// Assumes an AWS Identity and Access Management (IAM) role that allows
    /// Amazon S3 access for the current session.
    /// </summary>
    /// <param name="roleSession">A string representing the current session.</param>
    /// <param name="roleToAssume">The name of the IAM role to assume.</param>
    /// <returns>Credentials for the newly assumed IAM role.</returns>
    public async Task<Credentials> AssumeS3RoleAsync(string roleSession, string roleToAssume)
    {
        // Create the request to use with the AssumeRoleAsync call.
        var request = new AssumeRoleRequest()
        {
            RoleSessionName = roleSession,
            RoleArn = roleToAssume,
        };

        var response = await _stsService.AssumeRoleAsync(request);

        return response.Credentials;
    }

    /// <summary>
    /// Delete an S3 bucket.
    /// </summary>
    /// <param name="bucketName">Name of the S3 bucket to delete.</param>
    /// <returns>A Boolean value indicating the success of the action.</returns>
    public async Task<bool> DeleteBucketAsync(string bucketName)
    {
        var result = await _s3Service.DeleteBucketAsync(new DeleteBucketRequest { BucketName = bucketName });
        return result.HttpStatusCode == HttpStatusCode.OK;
    }

    /// <summary>
    /// List the buckets that are owned by the user's account.
    /// </summary>
    /// <returns>Async Task.</returns>
    public async Task<List<Amazon.S3.Model.S3Bucket>?> ListMyBucketsAsync()
    {
        try
        {
            // Get the list of buckets accessible by the new user.
            var response = await _s3Service.ListBucketsAsync();

            return response.Buckets;
        }
        catch (AmazonS3Exception ex)
        {
            // Something else went wrong. Display the error message.
            Console.WriteLine($"Error: {ex.Message}");
            return null;
        }
    }

    /// <summary>
    /// Create a new S3 bucket.
    /// </summary>
    /// <param name="bucketName">The name for the new bucket.</param>
    /// <returns>A Boolean value indicating whether the action completed
    /// successfully.</returns>
    public async Task<bool> PutBucketAsync(string bucketName)
    {
        var response = await _s3Service.PutBucketAsync(new PutBucketRequest { BucketName = bucketName });
        return response.HttpStatusCode == HttpStatusCode.OK;
    }

    /// <summary>
    /// Update the client objects with new client objects. This is available
    /// because the scenario uses the methods of this class without and then
    /// with the proper permissions to list S3 buckets.
    /// </summary>
    /// <param name="s3Service">The Amazon S3 client object.</param>
    /// <param name="stsService">The AWS STS client object.</param>
    public void UpdateClients(IAmazonS3 s3Service, IAmazonSecurityTokenService stsService)
    {
        _s3Service = s3Service;
        _stsService = stsService;
    }
}
```

## 8. Input the UIWrapper.cs code

This class enhances the user experience in a console-based tutorial or learning app by clearly presenting steps, pausing for user interaction, and formatting output nicely

It's **purely UI** logic—no AWS SDK calls or IAM logic here, just **support for the demo display**

```csharp
// Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0
namespace IamScenariosCommon;

public class UIWrapper
{
    public readonly string SepBar = new('-', Console.WindowWidth);

    /// <summary>
    /// Show information about the IAM Groups scenario.
    /// </summary>
    public void DisplayGroupsOverview()
    {
        Console.Clear();

        DisplayTitle("Welcome to the IAM Groups Demo");
        Console.WriteLine("This example application does the following:");
        Console.WriteLine("\t1. Creates an Amazon Identity and Access Management (IAM) group.");
        Console.WriteLine("\t2. Adds an IAM policy to the IAM group giving it full access to Amazon S3.");
        Console.WriteLine("\t3. Creates a new IAM user.");
        Console.WriteLine("\t4. Creates an IAM access key for the user.");
        Console.WriteLine("\t5. Adds the user to the IAM group.");
        Console.WriteLine("\t6. Lists the buckets on the account.");
        Console.WriteLine("\t7. Proves that the user has full Amazon S3 access by creating a bucket.");
        Console.WriteLine("\t8. List the buckets again to show the new bucket.");
        Console.WriteLine("\t9. Cleans up all the resources created.");
    }

    /// <summary>
    /// Show information about the IAM Basics scenario.
    /// </summary>
    public void DisplayBasicsOverview()
    {
        Console.Clear();

        DisplayTitle("Welcome to IAM Basics");
        Console.WriteLine("This example application does the following:");
        Console.WriteLine("\t1. Creates a user with no permissions.");
        Console.WriteLine("\t2. Creates a role and policy that grant s3:ListAllMyBuckets permission.");
        Console.WriteLine("\t3. Grants the user permission to assume the role.");
        Console.WriteLine("\t4. Creates an S3 client object as the user and tries to list buckets (this will fail).");
        Console.WriteLine("\t5. Gets temporary credentials by assuming the role.");
        Console.WriteLine("\t6. Creates a new S3 client object with the temporary credentials and lists the buckets (this will succeed).");
        Console.WriteLine("\t7. Deletes all the resources.");
    }

    /// <summary>
    /// Display a message and wait until the user presses enter.
    /// </summary>
    public void PressEnter()
    {
        Console.Write("\nPress <Enter> to continue. ");
        _ = Console.ReadLine();
        Console.WriteLine();
    }

    /// <summary>
    /// Pad a string with spaces to center it on the console display.
    /// </summary>
    /// <param name="strToCenter">The string to be centered.</param>
    /// <returns>The padded string.</returns>
    public string CenterString(string strToCenter)
    {
        var padAmount = (Console.WindowWidth - strToCenter.Length) / 2;
        var leftPad = new string(' ', padAmount);
        return $"{leftPad}{strToCenter}";
    }

    /// <summary>
    /// Display a line of hyphens, the centered text of the title, and another
    /// line of hyphens.
    /// </summary>
    /// <param name="strTitle">The string to be displayed.</param>
    public void DisplayTitle(string strTitle)
    {
        Console.WriteLine(SepBar);
        Console.WriteLine(CenterString(strTitle));
        Console.WriteLine(SepBar);
    }

    /// <summary>
    /// Display a countdown and wait for a number of seconds.
    /// </summary>
    /// <param name="numSeconds">The number of seconds to wait.</param>
    public void WaitABit(int numSeconds, string msg)
    {
        Console.WriteLine(msg);

        // Wait for the requested number of seconds.
        for (int i = numSeconds; i > 0; i--)
        {
            System.Threading.Thread.Sleep(1000);
            Console.Write($"{i}...");
        }

        PressEnter();
    }
}
```

## 9. Input the Program.cs (middleware) code

This code is a C# console application that demonstrates how to use the AWS Identity and Access Management (IAM) and Amazon S3 services programmatically using the AWS SDK for .NET

It simulates a scenario where an **IAM user is created** and gradually **granted permissions using IAM roles and policies**

### 9.1. Creates a User with No Permissions

**Program.cs**

```csharp
var user = await iamWrapper.CreateUserAsync(userName);
```

**IAMWrapper.cs**

```csharp
public async Task<User> CreateUserAsync(string userName)
{
    var response = await _IAMService.CreateUserAsync(new CreateUserRequest { UserName = userName });
    return response.User;
}
```

### 9.2. Create an Access Key for the new User

**Program.cs**

```csharp
var accessKey = await iamWrapper.CreateAccessKeyAsync(userName);
```

**IAMWrapper.cs**

```csharp
public async Task<AccessKey> CreateAccessKeyAsync(string userName)
{
   var response = await _IAMService.CreateAccessKeyAsync(new CreateAccessKeyRequest
   {
       UserName = userName,
   });

   return response.AccessKey;
}
```

### 9.3. Creates an IAM Role 

**Define a role** policy document that allows the new user to assume the role.

**Program.cs**

```csharp
string assumeRolePolicyDocument = "{" +
    "\"Version\": \"2012-10-17\"," +
    "\"Statement\": [{" +
        "\"Effect\": \"Allow\"," +
        "\"Principal\": {" +
        $"	\"AWS\": \"{userArn}\"" +
        "}," +
        "\"Action\": \"sts:AssumeRole\"" +
    "}]" +
"}";
```

```csharp
var roleArn = await iamWrapper.CreateRoleAsync(roleName, assumeRolePolicyDocument);
```

### 9.4. Define a IAM Policy to allow listing the S3 buckets

A role name is not case sensitive and must be unique to the account for which it is created

**Program.cs**

Define the policy, permission to list all buckets

```csharp
string policyDocument = "{" +
    "\"Version\": \"2012-10-17\"," +
    "	\"Statement\" : [{" +
        "	\"Action\" : [\"s3:ListAllMyBuckets\"]," +
        "	\"Effect\" : \"Allow\"," +
        "	\"Resource\" : \"*\"" +
    "}]" +
"}";
```

### 9.5. Create the IAM Policy 

**Program.cs**

```csharp
var policy = await iamWrapper.CreatePolicyAsync(s3PolicyName, policyDocument);
```

### 9.6. Attach the IAM Policy to the IAM Role

**Program.cs**

```csharp
await iamWrapper.AttachRolePolicyAsync(policy.Arn, roleName);
```

### 9.7. Grants the User permission to Assume the IAM Role

Use the AWS Security Token Service (AWS **STS**) to have the **user assume the role** we created.

**Program.cs**

```csharp
var stsClient2 = new AmazonSecurityTokenServiceClient(accessKeyId, secretAccessKey);

// Wait for the new credentials to become valid.
uiWrapper.WaitABit(10, "Waiting for the credentials to be valid.");

var assumedRoleCredentials = await s3Wrapper.AssumeS3RoleAsync("temporary-session", roleArn);

// Try again to list the buckets using the client created with
// the new user's credentials. This time, it should work.
var s3Client2 = new AmazonS3Client(assumedRoleCredentials);

s3Wrapper.UpdateClients(s3Client2, stsClient2);
```

### 9.8. Using temporary credentials to access S3 and list buckets

**Program.cs**

```csharp
buckets = await s3Wrapper.ListMyBucketsAsync();
```

### 9.9 Cleaning up the created AWS resources

**Program.cs**

```csharp
await iamWrapper.DetachRolePolicyAsync(policy.Arn, roleName);

await iamWrapper.DeletePolicyAsync(policy.Arn);

await iamWrapper.DeleteRoleAsync(roleName);

await iamWrapper.DeleteAccessKeyAsync(accessKeyId, userName);

await iamWrapper.DeleteUserAsync(userName);
```

### 9.10 Program.cs (source code) 

```csharp
// Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0
using Microsoft.Extensions.Configuration;

// Set up dependency injection for the AWS service.
using var host = Host.CreateDefaultBuilder(args)
    .ConfigureLogging(logging =>
        logging.AddFilter("System", LogLevel.Debug)
            .AddFilter<DebugLoggerProvider>("Microsoft", LogLevel.Information)
            .AddFilter<ConsoleLoggerProvider>("Microsoft", LogLevel.Trace))
    .ConfigureServices((_, services) =>
    services.AddAWSService<IAmazonIdentityManagementService>()
    .AddTransient<IAMWrapper>()
    .AddTransient<UIWrapper>()
    )
    .Build();

ILogger logger = null!;

logger = LoggerFactory.Create(builder => { builder.AddConsole(); })
    .CreateLogger<Program>();


IConfiguration configuration = new ConfigurationBuilder()
    .SetBasePath(Directory.GetCurrentDirectory())
    .AddJsonFile("settings.json") // Load test settings from .json file.
    .Build();

// Values needed for user, role, and policies.
string userName = configuration["UserName"]!;
string s3PolicyName = configuration["S3PolicyName"]!;
string roleName = configuration["RoleName"]!;


var iamWrapper = host.Services.GetRequiredService<IAMWrapper>();
var uiWrapper = host.Services.GetRequiredService<UIWrapper>();

uiWrapper.DisplayBasicsOverview();
uiWrapper.PressEnter();

// First create a user. By default, the new user has
// no permissions.
uiWrapper.DisplayTitle("Create User");
Console.WriteLine($"Creating a new user with user name: {userName}.");
var user = await iamWrapper.CreateUserAsync(userName);
var userArn = user.Arn;

Console.WriteLine($"Successfully created user: {userName} with ARN: {userArn}.");
uiWrapper.WaitABit(15, "Now let's wait for the user to be ready for use.");

// Define a role policy document that allows the new user
// to assume the role.
string assumeRolePolicyDocument = "{" +
    "\"Version\": \"2012-10-17\"," +
    "\"Statement\": [{" +
        "\"Effect\": \"Allow\"," +
        "\"Principal\": {" +
        $"	\"AWS\": \"{userArn}\"" +
        "}," +
        "\"Action\": \"sts:AssumeRole\"" +
    "}]" +
"}";

// Permissions to list all buckets.
string policyDocument = "{" +
    "\"Version\": \"2012-10-17\"," +
    "	\"Statement\" : [{" +
        "	\"Action\" : [\"s3:ListAllMyBuckets\"]," +
        "	\"Effect\" : \"Allow\"," +
        "	\"Resource\" : \"*\"" +
    "}]" +
"}";

// Create an AccessKey for the user.
uiWrapper.DisplayTitle("Create access key");
Console.WriteLine("Now let's create an access key for the new user.");
var accessKey = await iamWrapper.CreateAccessKeyAsync(userName);

var accessKeyId = accessKey.AccessKeyId;
var secretAccessKey = accessKey.SecretAccessKey;

Console.WriteLine($"We have created the access key with Access key id: {accessKeyId}.");

Console.WriteLine("Now let's wait until the IAM access key is ready to use.");
var keyReady = await iamWrapper.WaitUntilAccessKeyIsReady(accessKeyId);

// Now try listing the Amazon Simple Storage Service (Amazon S3)
// buckets. This should fail at this point because the user doesn't
// have permissions to perform this task.
uiWrapper.DisplayTitle("Try to display Amazon S3 buckets");
Console.WriteLine("Now let's try to display a list of the user's Amazon S3 buckets.");
var s3Client1 = new AmazonS3Client(accessKeyId, secretAccessKey);
var stsClient1 = new AmazonSecurityTokenServiceClient(accessKeyId, secretAccessKey);

var s3Wrapper = new S3Wrapper(s3Client1, stsClient1);
var buckets = await s3Wrapper.ListMyBucketsAsync();

Console.WriteLine(buckets is null
    ? "As expected, the call to list the buckets has returned a null list."
    : "Something went wrong. This shouldn't have worked.");

uiWrapper.PressEnter();

uiWrapper.DisplayTitle("Create IAM role");
Console.WriteLine($"Creating the role: {roleName}");

// Creating an IAM role to allow listing the S3 buckets. A role name
// is not case sensitive and must be unique to the account for which it
// is created.
var roleArn = await iamWrapper.CreateRoleAsync(roleName, assumeRolePolicyDocument);

uiWrapper.PressEnter();

// Create a policy with permissions to list S3 buckets.
uiWrapper.DisplayTitle("Create IAM policy");
Console.WriteLine($"Creating the policy: {s3PolicyName}");
Console.WriteLine("with permissions to list the Amazon S3 buckets for the account.");
var policy = await iamWrapper.CreatePolicyAsync(s3PolicyName, policyDocument);

// Wait 15 seconds for the IAM policy to be available.
uiWrapper.WaitABit(15, "Waiting for the policy to be available.");

// Attach the policy to the role you created earlier.
uiWrapper.DisplayTitle("Attach new IAM policy");
Console.WriteLine("Now let's attach the policy to the role.");
await iamWrapper.AttachRolePolicyAsync(policy.Arn, roleName);

// Wait 15 seconds for the role to be updated.
Console.WriteLine();
uiWrapper.WaitABit(15, "Waiting for the policy to be attached.");

// Use the AWS Security Token Service (AWS STS) to have the user
// assume the role we created.
var stsClient2 = new AmazonSecurityTokenServiceClient(accessKeyId, secretAccessKey);

// Wait for the new credentials to become valid.
uiWrapper.WaitABit(10, "Waiting for the credentials to be valid.");

var assumedRoleCredentials = await s3Wrapper.AssumeS3RoleAsync("temporary-session", roleArn);

// Try again to list the buckets using the client created with
// the new user's credentials. This time, it should work.
var s3Client2 = new AmazonS3Client(assumedRoleCredentials);

s3Wrapper.UpdateClients(s3Client2, stsClient2);

buckets = await s3Wrapper.ListMyBucketsAsync();

uiWrapper.DisplayTitle("List Amazon S3 buckets");
Console.WriteLine("This time we should have buckets to list.");
if (buckets is not null)
{
    buckets.ForEach(bucket =>
    {
        Console.WriteLine($"{bucket.BucketName} created: {bucket.CreationDate}");
    });
}

uiWrapper.PressEnter();

// Now clean up all the resources used in the example.
uiWrapper.DisplayTitle("Clean up resources");
Console.WriteLine("Thank you for watching. The IAM Basics demo is complete.");
Console.WriteLine("Please wait while we clean up the resources we created.");

await iamWrapper.DetachRolePolicyAsync(policy.Arn, roleName);

await iamWrapper.DeletePolicyAsync(policy.Arn);

await iamWrapper.DeleteRoleAsync(roleName);

await iamWrapper.DeleteAccessKeyAsync(accessKeyId, userName);

await iamWrapper.DeleteUserAsync(userName);

uiWrapper.PressEnter();

Console.WriteLine("All done cleaning up our resources. Thank you for your patience.");
```

## 10. Run the application and verify the results 

![image](https://github.com/user-attachments/assets/c92b8fa7-212c-429f-992e-5b2dc49b9565)

### 10.1. We Create a new User

![image](https://github.com/user-attachments/assets/f9122309-00bd-4a80-9b21-13e841e03ba2)

We confirmed a **new User was Created** in AWS Console

![image](https://github.com/user-attachments/assets/4805d49c-8679-41bb-89f4-761f886d2b8e)

### 10.2. We create an Access Key

![image](https://github.com/user-attachments/assets/1c74be72-ca2d-49cb-b9d8-a4a60fa6e45a)

We also confirm in AWS Console for the new user the access key was created

![image](https://github.com/user-attachments/assets/077704a8-4a19-43cc-b40f-de214071370b)

![image](https://github.com/user-attachments/assets/0fffc728-e9e2-4b4a-b6fb-aae0795feca4)

### 10.3. We create a new IAM Role

![image](https://github.com/user-attachments/assets/abb7f84d-2206-431f-98cd-a72d47b1f448)

We confirme the new role was created in AWS Console

![image](https://github.com/user-attachments/assets/3bd5b325-eda2-4881-8a51-4f88bdcfdade)

### 10.4. We create a new IAM Policy

![image](https://github.com/user-attachments/assets/3a7bcae4-2962-4141-b29a-16d3b3434b16)

We confirm the new IAM Policy was created in AWS Console

![image](https://github.com/user-attachments/assets/3ed755a5-d89e-4e3f-8bb4-367fbcdadaba)

### 10.5. We Attach the Policy to the Role

![image](https://github.com/user-attachments/assets/f00cb6d2-1840-4619-b04b-86475fb3cbc0)

We confirm in AWS Console the new IAM Policy was attached to the Role

![image](https://github.com/user-attachments/assets/271901c5-82b4-4c10-8938-69e02244f9d3)

### 10.6. We list buckets in the S3

![image](https://github.com/user-attachments/assets/53e7bc2f-d12d-4421-9052-c4db7b339bf1)





