import React, { useState } from 'react';
import { AnimatePresence, motion } from 'motion/react';
import { AlertTriangle } from 'lucide-react';
import { useConsole } from '../context/ConsoleContext.tsx';

export const ConfirmSheet: React.FC = () => {
  const { confirmReq, closeConfirm, pushToast } = useConsole();
  const [busy, setBusy] = useState(false);

  const handleConfirm = async () => {
    if (!confirmReq || busy) return;
    setBusy(true);
    try {
      await confirmReq.onConfirm();
      closeConfirm();
    } catch (err) {
      pushToast({
        title: 'Action failed',
        detail: err instanceof Error ? err.message : 'Unexpected error.',
        tone: 'error',
      });
    } finally {
      setBusy(false);
    }
  };

  return (
    <AnimatePresence>
      {confirmReq && (
        <motion.div
          initial={{ opacity: 0 }}
          animate={{ opacity: 1 }}
          exit={{ opacity: 0 }}
          transition={{ duration: 0.14 }}
          className="fixed inset-0 z-50 flex items-center justify-center bg-[#111827]/28 backdrop-blur-[4px] p-4"
          onClick={() => !busy && closeConfirm()}
        >
          <motion.div
            initial={{ opacity: 0, scale: 0.97, y: 6 }}
            animate={{ opacity: 1, scale: 1, y: 0 }}
            exit={{ opacity: 0, scale: 0.98, y: 4 }}
            transition={{ duration: 0.18, ease: [0.22, 1, 0.36, 1] }}
            className="surface-vibrancy-overlay w-full max-w-[440px] overflow-hidden rounded-[12px] border border-[#E5E7EB]/85"
            onClick={(e) => e.stopPropagation()}
          >
            <div className="flex items-start gap-3.5 p-5">
              <div
                className={`mt-0.5 flex h-8 w-8 shrink-0 items-center justify-center rounded-[8px] border ${
                  confirmReq.destructive
                    ? 'border-[#FECACA] bg-[#FEF2F2] text-[#DC2626]'
                    : 'border-[#BFDBFE] bg-[#EFF6FF] text-[#1D6CF0]'
                }`}
              >
                <AlertTriangle className="h-4 w-4" />
              </div>
              <div className="min-w-0">
                <h3 className="type-section text-[15px] leading-snug">
                  {confirmReq.title}
                </h3>
                <p className="mt-1.5 text-[13px] leading-relaxed text-[#4B5563]">
                  {confirmReq.message}
                </p>
              </div>
            </div>

            <div className="flex items-center justify-end gap-2 border-t border-[#E5E7EB]/80 bg-[#F8F9FA]/75 px-5 py-3">
              <button
                type="button"
                disabled={busy}
                onClick={closeConfirm}
                className="rounded-[7px] border border-[#D1D5DB] bg-white px-3.5 py-1.5 type-control text-[#374151] transition-colors hover:bg-[#F3F4F6] disabled:opacity-50 whitespace-nowrap shrink-0"
              >
                Cancel
              </button>
              <button
                type="button"
                disabled={busy}
                onClick={handleConfirm}
                className={`rounded-[7px] px-3.5 py-1.5 type-control text-white transition-colors disabled:opacity-50 whitespace-nowrap shrink-0 ${
                  confirmReq.destructive
                    ? 'bg-[#DC2626] hover:bg-[#B91C1C]'
                    : 'bg-[#1D6CF0] hover:bg-[#1558D6]'
                }`}
              >
                {busy ? 'Executing…' : confirmReq.confirmLabel}
              </button>
            </div>
          </motion.div>
        </motion.div>
      )}
    </AnimatePresence>
  );
};
