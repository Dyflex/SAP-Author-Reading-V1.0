sap.ui.require(
    [
        'sap/fe/test/JourneyRunner',
        'authorreadingmanager/test/integration/FirstJourney',
		'authorreadingmanager/test/integration/pages/AuthorReadingsList',
		'authorreadingmanager/test/integration/pages/AuthorReadingsObjectPage',
		'authorreadingmanager/test/integration/pages/ParticipantsObjectPage'
    ],
    function(JourneyRunner, opaJourney, AuthorReadingsList, AuthorReadingsObjectPage, ParticipantsObjectPage) {
        'use strict';
        var JourneyRunner = new JourneyRunner({
            // start index.html in web folder
            launchUrl: sap.ui.require.toUrl('authorreadingmanager') + '/index.html'
        });

       
        JourneyRunner.run(
            {
                pages: { 
					onTheAuthorReadingsList: AuthorReadingsList,
					onTheAuthorReadingsObjectPage: AuthorReadingsObjectPage,
					onTheParticipantsObjectPage: ParticipantsObjectPage
                }
            },
            opaJourney.run
        );
    }
);