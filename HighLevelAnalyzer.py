# High Level Analyzer
# For more information and documentation, please go to https://support.saleae.com/extensions/high-level-analyzer-extensions

from saleae.analyzers import HighLevelAnalyzer, AnalyzerFrame
import saleae


# High level analyzers must subclass the HighLevelAnalyzer class.
class Hla(HighLevelAnalyzer):

    # An optional list of types this analyzer produces, providing a way to customize the way frames are displayed in Logic 2.
    result_types = {
        'interrupt': {
            'format': 'interrupt: {{data.value}}, {{data.dir}}'
        },
        'overflow': {
            'format': 'overflow'
        },
        'timestamp': {
            'format': 'ts: {{data.value}}'
        }
    }

    def __init__(self):
        '''
        Initialize HLA.

        Settings can be accessed using the same name used above.
        '''

        self.interrupt_frame = []

        self.ts_frame = []
        self.ts = 0
        self.count = 0

    def decode(self, frame: AnalyzerFrame):
        '''
        Process a frame from the input analyzer, and optionally return a single `AnalyzerFrame` or a list of `AnalyzerFrame`s.

        The type and data values in `frame` will depend on the input analyzer.
        '''
        
        if len(self.interrupt_frame):
            if len(self.interrupt_frame) == 2:
                dir = 'unk'
                if frame.data['data'] == b'\x20':
                    dir = 'exit'
                elif frame.data['data'] == b'\x10':
                    dir = 'enter'
                elif frame.data['data'] == b'\x30':
                    dir = 'return'

                frame_out = AnalyzerFrame('interrupt', self.interrupt_frame[0].start_time, frame.end_time, {
                        'input_type': frame.type, 'value': int.from_bytes(self.interrupt_frame[1].data['data'],'big')-16,
                        'dir': dir
                    })
                self.interrupt_frame = []
                return frame_out
            else:
                self.interrupt_frame.append(frame)
        elif len(self.ts_frame):
            byte = int.from_bytes(frame.data['data'], 'big')
            if byte & 0x80:
                self.ts += (byte & 0x7F) << ((len(self.ts_frame)-1)*7)
                self.ts_frame.append(frame)
                return
            self.count += 1
            if (self.count < 5):
                print("btye " + str(byte))
                print("abc " + str((byte & 0x7F) << ((len(self.ts_frame)-1)*7)))
            self.ts += (byte & 0x7F) << ((len(self.ts_frame)-1)*7)
            frame_out =  AnalyzerFrame('timestamp', self.ts_frame[0].start_time, frame.end_time, {
                    'value': self.ts
                })
            self.ts_frame = []
            self.ts = 0
            return frame_out
        else:

            # Return the data frame itself
            if (frame.data['data'] == b'\x70'):
                return AnalyzerFrame('overflow', frame.start_time, frame.end_time, {
                    'input_type': frame.type, 'value': frame.data['data']
                })

            if (frame.data['data'] == b'\x0e'):
                self.interrupt_frame = [frame]
            
            if (frame.data['data'] == b'\xc0'):
                self.ts_frame = [frame]

