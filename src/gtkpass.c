/*
    gtkpass, a GTK password manager using libkpass
    Copyright (C) 2010 Brian De Wolf

    This program is free software: you can redistribute it and/or modify
    it under the terms of the GNU General Public License as published by
    the Free Software Foundation, either version 3 of the License, or
    (at your option) any later version.

    This program is distributed in the hope that it will be useful,
    but WITHOUT ANY WARRANTY; without even the implied warranty of
    MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
    GNU General Public License for more details.

    You should have received a copy of the GNU General Public License
    along with this program.  If not, see <http://www.gnu.org/licenses/>.
*/


#include <gtk/gtk.h>
#include <sys/mman.h>
#include <stdio.h>
#include <sys/stat.h>
#include <fcntl.h>
#include <stdlib.h>
#include <termios.h>
#include <unistd.h>
#include <string.h>
#include <errno.h>

#include <kpass.h>

#include "config.h"

enum {
	TL_TITLE,
	TL_TITLE_WEIGHT,
	TL_USERNAME,
	TL_PASSWORD,
	TL_URL,
	TL_MTIME,
	TL_MTIME_EPOCH,
	TL_STRUCT,
	TL_META_INFO,
};

enum {
	SORTID_GROUPS_ON_TOP,
};

enum {
	CB_OPEN=1,
	CB_CLOSE,
	CB_COPY,
};

	

gboolean walkprint(GtkTreeModel *model,
			GtkTreePath *path,
			GtkTreeIter *iter,
			gpointer data) {
	gchar *name, *tree_path_str;
	guint name_weight;

	gtk_tree_model_get(model, iter,
			TL_TITLE, &name,
			TL_TITLE_WEIGHT, &name_weight,
			-1);
	tree_path_str = gtk_tree_path_to_string(path);


	g_print ("Row %s: %s %d\n", tree_path_str, name, name_weight);

	g_free(tree_path_str);

	g_free(name);

	return FALSE;
}


void add_keys_of_group(struct kpass_db *db, GtkTreeStore *ts, GtkTreeIter *parent, int group) {
	int i;
	GtkTreeIter iter;
//	struct tm tms;
//	char time[64];

//	memset(&tms, 0, sizeof(tms));

	for(i = 0; i < db->entries_len; i++) {
		if(db->entries[i]->group_id == group) {
//			kpass_unpack_time(db->entries[i]->mtime, &tms);
//			strftime(time, 64, "%F", &tms);
			gtk_tree_store_append(ts, &iter, parent);
			gtk_tree_store_set(ts, &iter,
					TL_TITLE,  db->entries[i]->title,
					TL_TITLE_WEIGHT, PANGO_WEIGHT_NORMAL,
					TL_USERNAME, db->entries[i]->username,
					TL_PASSWORD, db->entries[i]->password,
					TL_URL, db->entries[i]->url,
					TL_STRUCT, db->entries[i],
					TL_MTIME, time,
					-1);
		}
	}
}

int add_subgroups_to_store(struct kpass_db *db, GtkTreeStore *ts, GtkTreeIter *parent, int index, int l) {
	GtkTreeIter iter;
	int i = index;
//	struct tm tms;
//	char time[64];

	while(i < db->groups_len && db->groups[i]->level >= l) {
		if(db->groups[i]->level == l) {
//			kpass_unpack_time(db->groups[i]->mtime, &tms);
//			strftime(time, 64, "%c", &tms);
			gtk_tree_store_append(ts, &iter, parent);
			gtk_tree_store_set(ts, &iter,
					TL_TITLE, db->groups[i]->name,
					TL_TITLE_WEIGHT, PANGO_WEIGHT_BOLD,
					TL_STRUCT, db->groups[i],
/*					TL_MTIME, time,*/
					-1);
			add_keys_of_group(db, ts, &iter, db->groups[i]->id);
		} else if (db->groups[i]->level == l + 1) {
			i += add_subgroups_to_store(db, ts, &iter, i, l + 1);
		}
		i++;
	}
	return i - index - 1;
}

void add_groups_to_store(struct kpass_db *db, char* name, GtkTreeStore *ts) {
	GtkTreeIter iter;
	gtk_tree_store_append(ts, &iter, NULL);
	gtk_tree_store_set(ts, &iter,
			TL_TITLE, basename(name),
			TL_TITLE_WEIGHT, PANGO_WEIGHT_NORMAL+1,
			TL_STRUCT, db,
			-1);
	add_subgroups_to_store(db, ts, &iter, 0, 0);
}

/* -1: open failed
 * -2: fstat failed
 * -3: mmap failed
 *  All others are kpass errors
 */
int load_db_to_ts(char *filename, char *pass, GtkTreeStore *ts) {
	uint8_t *file = NULL;
	int length;
	int fd;
	struct stat sb;
	unsigned char pw_hash[32];
	kpass_db *db;
	kpass_retval retval = 0;
	uint8_t *outdb;
	int outdb_len;

	db = malloc(sizeof(kpass_db));

	memset(db, 0, sizeof(kpass_db));

	fd = open(filename, O_RDONLY);
	if(fd == -1) {
		return -1;
	}

	if(fstat(fd, &sb) == -1) {
		close(fd);
		return -2;
	}

	length = sb.st_size;

	file = mmap(NULL, length, PROT_READ, MAP_SHARED, fd, 0);
	if(file == MAP_FAILED) {
		close(fd);
		return -3;
	}
	retval = kpass_init_db(db, file, length);
	if(retval) goto load_db_to_ts_fail;

	retval = kpass_hash_pw(db, pass, pw_hash);
	if(retval) goto load_db_to_ts_fail;
	
	retval = kpass_decrypt_db(db, pw_hash);
	if(retval) goto load_db_to_ts_fail;

	add_groups_to_store(db, filename, ts);

load_db_to_ts_fail:
	munmap(file, length);
	close(fd);

//	kpass_free_db(&db);
//	free(db);
	return retval;
}

void menu_close(GtkWidget *widget, gpointer callback_data) {
	GtkTreeView *tv = GTK_TREE_VIEW(callback_data);
	GtkTreeModel *ts = gtk_tree_view_get_model(tv);
	GtkTreePath *path;
	GtkTreeViewColumn *col;
	GtkTreeIter iter;
	kpass_db *db;

	gtk_tree_view_get_cursor(tv, &path, &col);

	if(!path) return;

	while(gtk_tree_path_get_depth(path) > 1) gtk_tree_path_up(path);

	gtk_tree_model_get_iter(ts, &iter, path);

	gtk_tree_model_get(ts, &iter,
			TL_STRUCT, &db,
			-1);

	kpass_free_db(db);
	free(db);

	gtk_tree_store_remove(GTK_TREE_STORE(ts), &iter);

	gtk_tree_path_free(path);
}

void menu_copy_pw(GtkWidget *widget, gpointer callback_data) {
	GtkTreeView *tv = GTK_TREE_VIEW(callback_data);
	GtkTreeModel *ts = gtk_tree_view_get_model(tv);
	GtkTreePath *path;
	GtkTreeViewColumn *col;
	GtkTreeIter iter;
	gchar *val;

	gtk_tree_view_get_cursor(tv, &path, &col);

	if(!path) return;

	gtk_tree_model_get_iter(ts, &iter, path);

	gtk_tree_model_get(ts, &iter,
			TL_PASSWORD, &val,
			-1);

	if(val && strlen(val) > 0) {
		gtk_clipboard_set_text(gtk_clipboard_get(GDK_SELECTION_CLIPBOARD), val, -1);
		gtk_clipboard_set_text(gtk_clipboard_get(GDK_SELECTION_PRIMARY), val, -1);
	}

	gtk_tree_path_free(path);
}

void menu_copy_un(GtkWidget *widget, gpointer callback_data) {
	GtkTreeView *tv = GTK_TREE_VIEW(callback_data);
	GtkTreeModel *ts = gtk_tree_view_get_model(tv);
	GtkTreePath *path;
	GtkTreeViewColumn *col;
	GtkTreeIter iter;
	gchar *val;

	gtk_tree_view_get_cursor(tv, &path, &col);

	if(!path) return;

	gtk_tree_model_get_iter(ts, &iter, path);

	gtk_tree_model_get(ts, &iter,
			TL_USERNAME, &val,
			-1);

	if(val && strlen(val) > 0) {
		gtk_clipboard_set_text(gtk_clipboard_get(GDK_SELECTION_CLIPBOARD), val, -1);
		gtk_clipboard_set_text(gtk_clipboard_get(GDK_SELECTION_PRIMARY), val, -1);
	}

	gtk_tree_path_free(path);
}

void menu_quit(GtkWidget *widget, gpointer data1, gpointer data2) {
	GtkTreeView *tv;
	GtkTreeModel *ts;

	if(GTK_IS_TREE_VIEW(data1))
		tv = GTK_TREE_VIEW(data1);
	else
		tv = GTK_TREE_VIEW(data2);
	ts = gtk_tree_view_get_model(tv);

	/* Should probably clean up kpass databases here... */

	gtk_main_quit();
}

void menu_open(GtkWidget *widget, gpointer callback_data) {
	GtkTreeView *tv = GTK_TREE_VIEW(callback_data);
	GtkTreeModel *ts = gtk_tree_view_get_model(tv);
	GtkWidget *dialog_f, *dialog_p, *mdialog_p, *label_p, *entry_p;
	GtkFileFilter *filter;
	GtkTreeIter iter;
	char *filename;
	int retval;

	/* Set up file chooser */
	dialog_f = gtk_file_chooser_dialog_new ("Open File",
			NULL,
			GTK_FILE_CHOOSER_ACTION_OPEN,
			GTK_STOCK_CANCEL, GTK_RESPONSE_CANCEL,
			GTK_STOCK_OPEN, GTK_RESPONSE_ACCEPT,
			NULL);

	filter = gtk_file_filter_new();
	gtk_file_filter_add_pattern(filter, "*.kdb");
	gtk_file_filter_set_name(filter, "KeePass files");
	gtk_file_chooser_add_filter(GTK_FILE_CHOOSER (dialog_f), filter);

	filter = gtk_file_filter_new();
	gtk_file_filter_add_pattern(filter, "*");
	gtk_file_filter_set_name(filter, "All files");
	gtk_file_chooser_add_filter(GTK_FILE_CHOOSER (dialog_f), filter);

	/* Set up password entry */
	dialog_p = gtk_dialog_new_with_buttons("Password", NULL, 0, GTK_STOCK_OK, GTK_RESPONSE_ACCEPT, GTK_STOCK_CANCEL, GTK_RESPONSE_REJECT, NULL);
	gtk_dialog_set_default_response(GTK_DIALOG(dialog_p), GTK_RESPONSE_ACCEPT);


	label_p = gtk_label_new("Enter the password for this database:");
	entry_p = gtk_entry_new();
	gtk_entry_set_visibility(GTK_ENTRY(entry_p), FALSE);
	gtk_entry_set_activates_default(GTK_ENTRY(entry_p), TRUE);
//	gtk_container_add(GTK_CONTAINER(gtk_dialog_get_content_area (GTK_DIALOG (dialog_p))),label_p);
	gtk_container_add(GTK_CONTAINER(gtk_dialog_get_content_area (GTK_DIALOG (dialog_p))),entry_p);
	gtk_widget_show (entry_p);

	if (gtk_dialog_run (GTK_DIALOG (dialog_f)) == GTK_RESPONSE_ACCEPT){
		filename = gtk_file_chooser_get_filename (GTK_FILE_CHOOSER (dialog_f));
		gtk_widget_hide(dialog_f);

		while (gtk_dialog_run(GTK_DIALOG (dialog_p)) == GTK_RESPONSE_ACCEPT) {
			retval = load_db_to_ts(filename, (char*)gtk_entry_get_text(GTK_ENTRY(entry_p)), GTK_TREE_STORE(ts));
			if(!retval)
				break;
			if(retval > 0)
				mdialog_p = gtk_message_dialog_new(GTK_WINDOW(dialog_p), GTK_DIALOG_DESTROY_WITH_PARENT, GTK_MESSAGE_ERROR, GTK_BUTTONS_CLOSE, "Error loading database: %s", kpass_error_str[retval]);
			else
				mdialog_p = gtk_message_dialog_new(GTK_WINDOW(dialog_p), GTK_DIALOG_DESTROY_WITH_PARENT, GTK_MESSAGE_ERROR, GTK_BUTTONS_CLOSE, "Error opening file: %s", g_strerror(errno));

			gtk_dialog_run (GTK_DIALOG (mdialog_p));
			gtk_widget_destroy (mdialog_p);
			
		}
		gtk_widget_destroy (dialog_p);
	}
	gtk_widget_destroy (dialog_f);
}

gint sort_iter_compare_func (GtkTreeModel *model,
		GtkTreeIter  *a,
		GtkTreeIter  *b,
		gpointer      userdata) {

	gchar *name1, *name2;
	gint sortcol = GPOINTER_TO_INT(userdata), ret = 0;
	gint weight1, weight2;

	switch(sortcol) {
		case SORTID_GROUPS_ON_TOP:
			gtk_tree_model_get(model, a, TL_TITLE_WEIGHT, &weight1, -1);
			gtk_tree_model_get(model, b, TL_TITLE_WEIGHT, &weight2, -1);

			if(weight1 != weight2) {
				ret = (weight1 > weight2) ? -1 : 1;
				break;
			}
			gtk_tree_model_get(model, a, TL_TITLE, &name1, -1);
			gtk_tree_model_get(model, b, TL_TITLE, &name2, -1);
			if(!name1 || !name2) {
				if(!name1 && !name2)
					break;
				ret = (name1)? -1 : 1;
			} else {
				ret = g_utf8_collate(name1,name2);
			}
			g_free(name1);
			g_free(name2);
			break;
		default:
			break;
	}

	return ret;
}



static char *ui_xml = " \
<ui> \
	<menubar name=\"MainMenu\"> \
		<menu name=\"FileMenu\" action=\"FileMenuAction\"> \
			<menuitem name=\"Open\" action=\"OpenAction\" /> \
			<menuitem name=\"Close\" action=\"CloseAction\" /> \
			<separator/> \
			<menuitem name=\"Quit\" action=\"QuitAction\" /> \
		</menu> \
		<menu name=\"GroupMenu\" action=\"GroupMenuAction\"> \
		</menu> \
		<menu name=\"EntryMenu\" action=\"EntryMenuAction\"> \
			<menuitem name=\"Copy Password\" action=\"CopyAction\" /> \
			<menuitem name=\"Copy Password\" action=\"CopyPWAction\" /> \
			<menuitem name=\"Copy Username\" action=\"CopyUNAction\" /> \
		</menu> \
	</menubar> \
	<popup name=\"EntryPop\" action=\"EntryPopAction\"> \
		<menuitem name=\"Copy Password\" action=\"CopyAction\" /> \
		<menuitem name=\"Copy Password\" action=\"CopyPWAction\" /> \
		<menuitem name=\"Copy Username\" action=\"CopyUNAction\" /> \
	</popup> \
</ui>";

static GtkActionEntry entries[] = 
{
  { "FileMenuAction", NULL, "_File" },
  { "GroupMenuAction", NULL, "_Group" },
  { "EntryMenuAction", NULL, "_Entry" },
    
  { "OpenAction", GTK_STOCK_OPEN,
    "_Open","<control>O",  
    "Open a new file",
    G_CALLBACK (menu_open) },
    
  { "CloseAction", GTK_STOCK_CLOSE,
    "_Close","",  
    "Close the selected file",
    G_CALLBACK (menu_close) },

  { "QuitAction", GTK_STOCK_QUIT,
    "_Quit", "<control>Q",    
    "Quit",
    G_CALLBACK (menu_quit) },

  { "CopyPWAction", GTK_STOCK_COPY,
    "_Copy Password", "<control>C",
    "Copy password of entry to clipboard",
    G_CALLBACK (menu_copy_pw) },

  { "CopyUNAction", GTK_STOCK_COPY,
    "_Copy Username", "<control>B",    
    "Copy username of entry to clipboard",
    G_CALLBACK (menu_copy_un) },
};

static guint n_entries = G_N_ELEMENTS (entries);

int main( int argc, char *argv[] ) {
	GtkTreeStore *ts;
	GtkWidget *view, *window, *menubar, *window_box, *view_scroller;
	GtkTreeViewColumn   *col;
	GtkCellRenderer     *renderer;
	GtkTreeSortable *sortable;
	GtkUIManager *menu_manager;
	GError *error;
	GtkActionGroup *action_group;
	GdkPixbuf *icon;


	gtk_init(&argc, &argv);

	/* set up GTK */
	ts = gtk_tree_store_new (9,
	G_TYPE_STRING, G_TYPE_UINT, G_TYPE_STRING, G_TYPE_STRING, G_TYPE_STRING, G_TYPE_STRING, G_TYPE_UINT, G_TYPE_POINTER, G_TYPE_BOOLEAN);
/*	TL_TITLE, TL_TITLE_WEIGHT, TL_USERNAME, TL_PASSWORD, TL_URL, TL_MTIME, TL_MTIME_EPOCH, TL_STRUCT, TL_META_INFO */

	sortable = GTK_TREE_SORTABLE(ts);
	gtk_tree_sortable_set_sort_func(sortable, SORTID_GROUPS_ON_TOP, sort_iter_compare_func, GINT_TO_POINTER(SORTID_GROUPS_ON_TOP), NULL);
	gtk_tree_sortable_set_sort_column_id(sortable, SORTID_GROUPS_ON_TOP, GTK_SORT_ASCENDING);



	gtk_tree_model_foreach(GTK_TREE_MODEL(ts), walkprint, NULL);

	view = gtk_tree_view_new();
	col = gtk_tree_view_column_new();
	gtk_tree_view_column_set_title(col, "Title");
	gtk_tree_view_append_column(GTK_TREE_VIEW(view), col);
	renderer = gtk_cell_renderer_text_new();
	gtk_tree_view_column_pack_start(col, renderer, TRUE);
	gtk_tree_view_column_add_attribute(col, renderer, "text", TL_TITLE);
	gtk_tree_view_column_add_attribute(col, renderer, "weight", TL_TITLE_WEIGHT);
/*	Save this tidbit for when we want RW databases
	g_object_set(renderer, "editable", TRUE, NULL);
*/

	col = gtk_tree_view_column_new();
	gtk_tree_view_column_set_title(col, "Username");
	gtk_tree_view_append_column(GTK_TREE_VIEW(view), col);
	renderer = gtk_cell_renderer_text_new();
	gtk_tree_view_column_pack_start(col, renderer, TRUE);
	gtk_tree_view_column_add_attribute(col, renderer, "text", TL_USERNAME);

	col = gtk_tree_view_column_new();
	gtk_tree_view_column_set_title(col, "URL");
	gtk_tree_view_append_column(GTK_TREE_VIEW(view), col);
	renderer = gtk_cell_renderer_text_new();
	gtk_tree_view_column_pack_start(col, renderer, TRUE);
	gtk_tree_view_column_add_attribute(col, renderer, "text", TL_URL);

/*
	col = gtk_tree_view_column_new();
	gtk_tree_view_column_set_title(col, "Modified");
	gtk_tree_view_append_column(GTK_TREE_VIEW(view), col);
	renderer = gtk_cell_renderer_text_new();
	gtk_tree_view_column_pack_start(col, renderer, TRUE);
	gtk_tree_view_column_add_attribute(col, renderer, "text", TL_MTIME);
*/
/*	
	col = gtk_tree_view_column_new();
	gtk_tree_view_column_set_title(col, "Is group");
	gtk_tree_view_append_column(GTK_TREE_VIEW(view), col);
	renderer = gtk_cell_renderer_text_new();
	gtk_tree_view_column_pack_start(col, renderer, TRUE);
	gtk_tree_view_column_add_attribute(col, renderer, "text", TL_ISGROUP);
*/

	gtk_tree_view_set_model(GTK_TREE_VIEW(view), GTK_TREE_MODEL(ts));
	g_object_unref(ts);

	gtk_tree_selection_set_mode(
			gtk_tree_view_get_selection(GTK_TREE_VIEW(view)),
			GTK_SELECTION_SINGLE);

	view_scroller = gtk_scrolled_window_new(NULL, NULL);
	gtk_scrolled_window_set_policy(GTK_SCROLLED_WINDOW(view_scroller), GTK_POLICY_AUTOMATIC, GTK_POLICY_AUTOMATIC);
	gtk_container_add(GTK_CONTAINER(view_scroller), view);

	window = gtk_window_new(GTK_WINDOW_TOPLEVEL);
	icon = gdk_pixbuf_new_from_file(ICONDIR G_DIR_SEPARATOR_S PACKAGE ".png", NULL);
	gtk_window_set_title(GTK_WINDOW(window), PACKAGE);
	gtk_window_set_icon(GTK_WINDOW(window), icon);

	g_signal_connect(window, "delete_event", G_CALLBACK(menu_quit), view);
	gtk_window_set_default_size (GTK_WINDOW (window), 400, 400);

	menu_manager = gtk_ui_manager_new();
	action_group = gtk_action_group_new("gtkpass");
	gtk_action_group_add_actions (action_group, entries, n_entries, view);
	gtk_ui_manager_insert_action_group (menu_manager, action_group, 0);

	error = NULL;
	gtk_ui_manager_add_ui_from_string(menu_manager, ui_xml, strlen(ui_xml), &error);

	if(error) {
		g_message("building menus failed: %s", error->message);
		g_error_free(error);
		exit(1);
	}

	menubar = gtk_ui_manager_get_widget(menu_manager, "/MainMenu");

	gtk_window_add_accel_group (GTK_WINDOW (window), 
		gtk_ui_manager_get_accel_group (menu_manager));


	window_box = gtk_vbox_new(FALSE, 1);
	gtk_container_set_border_width (GTK_CONTAINER (window_box), 0);
	gtk_container_add (GTK_CONTAINER (window), window_box);

	gtk_box_pack_start (GTK_BOX (window_box), menubar, FALSE, TRUE, 0);
        gtk_box_pack_end (GTK_BOX (window_box), view_scroller, TRUE, TRUE, 0);

	gtk_widget_show_all(window);

	gtk_main();

	return 0;
}
