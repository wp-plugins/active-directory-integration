xgettext --keyword=__ --keyword=_e --from-code=UTF-8 --default-domain=ad-integration --output=ad-integration.pot ad-integration.php admin.php
msgmerge --update ad-integration-de_DE.po ad-integration.pot
msgmerge --update ad-integration-nl_NL.po ad-integration.pot
msgmerge --update ad-integration-be_BY.po ad-integration.pot
msgmerge --update ad-integration-nb_NO.po ad-integration.pot