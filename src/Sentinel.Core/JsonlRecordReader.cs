using System;
using System.IO;
using System.Text;
using System.Threading;
using System.Threading.Tasks;

namespace Sentinel.Core
{
    /// <summary>Byte offsets are committed only at newline boundaries, including UTF-8 records.</summary>
    internal static class JsonlRecordReader
    {
        internal static async Task<long> ReadAsync(Stream stream, long offset, Func<string, Task> accept,
            CancellationToken ct)
        {
            using var pending = new MemoryStream();
            var buffer = new byte[4096];
            long committed = offset;
            bool oversized = false;
            int count;
            while ((count = await stream.ReadAsync(buffer, 0, buffer.Length, ct).ConfigureAwait(false)) > 0)
            {
                for (int i = 0; i < count; i++)
                {
                    ct.ThrowIfCancellationRequested();
                    offset++;
                    if (buffer[i] != (byte)'\n')
                    {
                        if (pending.Length < 65536 && !oversized) pending.WriteByte(buffer[i]);
                        else oversized = true;
                        continue;
                    }
                    if (oversized) throw new InvalidDataException("Consultant JSONL record exceeds 64 KiB");
                    var line = Encoding.UTF8.GetString(pending.ToArray()).TrimEnd('\r');
                    if (!string.IsNullOrWhiteSpace(line)) await accept(line).ConfigureAwait(false);
                    pending.SetLength(0);
                    committed = offset;
                }
            }
            return committed;
        }
    }
}
