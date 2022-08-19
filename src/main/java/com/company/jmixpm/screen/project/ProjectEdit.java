package com.company.jmixpm.screen.project;

import com.company.jmixpm.entity.Project;
import com.company.jmixpm.entity.User;
import io.jmix.core.SaveContext;
import io.jmix.core.UnconstrainedDataManager;
import io.jmix.core.security.CurrentAuthentication;
import io.jmix.core.usersubstitution.CurrentUserSubstitution;
import io.jmix.ui.screen.*;
import org.springframework.beans.factory.annotation.Autowired;

import java.util.Set;

@UiController("Project.edit")
@UiDescriptor("project-edit.xml")
@EditedEntityContainer("projectDc")
public class ProjectEdit extends StandardEditor<Project> {
    @Autowired
    private CurrentAuthentication currentAuthentication;

    @Autowired
    private CurrentUserSubstitution currentUserSubstitution;

    @Subscribe
    public void onInitEntity(InitEntityEvent<Project> event) {
        User user = (User) currentUserSubstitution.getSubstitutedUser();

        event.getEntity().setManager(user);
    }
}