package com.company.jmixpm.screen.document;

import com.company.jmixpm.entity.Document;
import io.jmix.ui.screen.LookupComponent;
import io.jmix.ui.screen.StandardLookup;
import io.jmix.ui.screen.UiController;
import io.jmix.ui.screen.UiDescriptor;

@UiController("Document.browse")
@UiDescriptor("document-browse.xml")
@LookupComponent("documentsTable")
public class DocumentBrowse extends StandardLookup<Document> {
}