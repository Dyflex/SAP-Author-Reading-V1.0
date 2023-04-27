using {AuthorReadingManager} from './service-models';

// ----------------------------------------------------------------------------
// Required authorization roles
annotate AuthorReadingManager with @(requires : [
    'AuthorReadingManagerRole-SAP',
    'AuthorReadingAdminRole-SAP'
]);

// ----------------------------------------------------------------------------
// Restriction per authorization role:

// Managers can read all author readings, create new author readings and change their own author readings
// Administrators have no restrictions
annotate AuthorReadingManager.AuthorReadings with @(restrict : [
    {
        grant : [
            'READ',
            'CREATE'
        ],
        to    : 'AuthorReadingManagerRole-SAP'
    },
    {
        grant : ['*'],
        to    : 'AuthorReadingManagerRole-SAP',
        where : 'createdBy = $user'
    },
    {
        grand : ['*'],
        to    : 'AuthorReadingAdminRole-SAP'
    }
]);

// Managers can read all participants, add new participants, change participants they added themseves
// Administrators have no restrictions
annotate AuthorReadingManager.Participants with @(restrict : [
    {
        grant : [
            'READ',
            'CREATE'
        ],
        to    : 'AuthorReadingManagerRole-SAP'
    },
    {
        grant : ['*'],
        to    : 'AuthorReadingManagerRole-SAP',
        where : 'createdBy = $user'
    },
    {
        grand : ['*'],
        to    : 'AuthorReadingAdminRole-SAP'
    }
]);

// ByD projects: Managers and Administrators can read and create remote projects
annotate AuthorReadingManager.ByDProjects with @(restrict : [
    {
        grant : ['*'],
        to    : 'AuthorReadingManagerRole-SAP',
    },
    {
        grand : ['*'],
        to    : 'AuthorReadingAdminRole-SAP'
    }
]);
annotate AuthorReadingManager.ByDProjectSummaryTasks with @(restrict : [
    {
        grant : ['*'],
        to    : 'AuthorReadingManagerRole-SAP',
    },
    {
        grand : ['*'],
        to    : 'AuthorReadingAdminRole-SAP'
    }
]);
annotate AuthorReadingManager.ByDProjectTasks with @(restrict : [
    {
        grant : ['*'],
        to    : 'AuthorReadingManagerRole-SAP',
    },
    {
        grand : ['*'],
        to    : 'AuthorReadingAdminRole-SAP'
    }
]);
annotate AuthorReadingManager.ByDProjectsTechUser with @(restrict : [
    {
        grant : ['*'],
        to    : 'AuthorReadingManagerRole-SAP',
    },
    {
        grand : ['*'],
        to    : 'AuthorReadingAdminRole-SAP'
    }
]);