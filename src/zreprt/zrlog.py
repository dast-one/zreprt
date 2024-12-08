import logging


class _SarifNotificationKeeper(logging.NullHandler):
    sarif_notii = list()  # A tricky class-var to store log to be included into SARIF file

    def handle(self, *args):
        self.__class__.sarif_notii.append(*args)


logging.getLogger('zreprt.zr2sarif').addHandler(_SarifNotificationKeeper())

notii = logging.getLogger('zreprt.zr2sarif')
