package com.company.jmixpm.screen.document;

import com.company.jmixpm.entity.Document;
import io.jmix.ui.screen.EditedEntityContainer;
import io.jmix.ui.screen.StandardEditor;
import io.jmix.ui.screen.UiController;
import io.jmix.ui.screen.UiDescriptor;

@UiController("Document.edit")
@UiDescriptor("document-edit.xml")
@EditedEntityContainer("documentDc")
public class DocumentEdit extends StandardEditor<Document> {
}