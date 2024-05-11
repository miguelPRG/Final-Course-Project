using System;
using System.Collections.Generic;
using System.Collections.Immutable;
using System.Linq;
using System.Threading.Tasks;
using Microsoft.CodeAnalysis;
using Microsoft.CodeAnalysis.CSharp;
using Microsoft.CodeAnalysis.CSharp.Syntax;
using Microsoft.CodeAnalysis.Diagnostics;
using ProjetoA.Classes;
using System.Collections.Concurrent;
using System.Text;
using System.Reflection;

namespace ProjetoA.Analyzers
{
    internal enum NivelRisco
    {
        Alto,
        Medio,
        Baixo
    }

    internal class Vulnerability
    {
        public string Tipo { get; }
        public string Codigo { get; }
        public List<int> Linhas { get; }
        public NivelRisco Risco { get; }

        public Vulnerability(string type, string code, NivelRisco riskLevel, List<int> linhas)
        {
            Tipo = type;
            Codigo = code;
            Risco = riskLevel;
            Linhas = linhas;
        }
    }

    internal class VulnerabilityAnalyzer
    {
        private readonly object _lock = new object();

        public async Task<List<Vulnerability>> Analyze(SyntaxTree tree)
        {
            var vulnerabilities = new List<Vulnerability>();

            var compilation = CSharpCompilation.Create("MyCompilation", new[] { tree }, new[]
            {
                MetadataReference.CreateFromFile(typeof(object).Assembly.Location)
            });

            var model = compilation.GetSemanticModel(tree);

            await Task.WhenAll(
                AnalyzeSqlInjection(tree, model, vulnerabilities),
                AnalyzeXss(tree, model, vulnerabilities)
            );

            return vulnerabilities;
        }

        private async Task AnalyzeSqlInjection(SyntaxTree tree, SemanticModel model, List<Vulnerability> vulnerabilities)
        {
            await Task.Run(() =>
            {
                var root = tree.GetRoot();

                var invocations = root.DescendantNodes().OfType<InvocationExpressionSyntax>();
                foreach (var invocation in invocations)
                {
                    var symbolInfo = model.GetSymbolInfo(invocation);
                    if (symbolInfo.Symbol != null)
                    {
                        if (symbolInfo.Symbol.ToString().StartsWith("System.Data.SqlClient.SqlCommand.ExecuteNonQuery"))
                        {
                            var argumentList = invocation.ArgumentList.Arguments;
                            if (argumentList.Count > 0 && argumentList[0].Expression is LiteralExpressionSyntax)
                            {
                                var lineNumber = ((LiteralExpressionSyntax)argumentList[0].Expression).GetLocation().GetLineSpan().StartLinePosition.Line +1;
                                lock (_lock)
                                {
                                    var existingVulnerability = vulnerabilities.FirstOrDefault(v => v.Tipo == "SQL Injection" && v.Codigo == invocation.ToString());
                                    if (existingVulnerability != null)
                                    {
                                        existingVulnerability.Linhas.Add(lineNumber);
                                    }
                                    else
                                    {
                                        vulnerabilities.Add(new Vulnerability("SQL Injection", invocation.ToString(), NivelRisco.Alto, new List<int> { lineNumber }));
                                    }
                                }
                            }
                        }
                    }
                }
            });
        }

        private async Task AnalyzeXss(SyntaxTree tree, SemanticModel model, List<Vulnerability> vulnerabilities)
        {
            await Task.Run(() =>
            {
                var root = tree.GetRoot();

                var assignments = root.DescendantNodes().OfType<AssignmentExpressionSyntax>();
                foreach (var assignment in assignments)
                {
                    var symbolInfo = model.GetSymbolInfo(assignment.Left);
                    if (symbolInfo.Symbol != null)
                    {
                        if (symbolInfo.Symbol.ToString().StartsWith("System.Web.UI.WebControls.Literal.Text"))
                        {
                            if (assignment.Right is LiteralExpressionSyntax)
                            {
                                var lineNumber = ((LiteralExpressionSyntax)assignment.Right).GetLocation().GetLineSpan().StartLinePosition.Line + 1;
                                lock (_lock)
                                {
                                    var existingVulnerability = vulnerabilities.FirstOrDefault(v => v.Tipo == "XSS" && v.Codigo == assignment.ToString());
                                    if (existingVulnerability != null)
                                    {
                                        existingVulnerability.Linhas.Add(lineNumber);
                                    }
                                    else
                                    {
                                        vulnerabilities.Add(new Vulnerability("XSS", assignment.ToString(), NivelRisco.Alto, new List<int> { lineNumber }));
                                    }
                                }
                            }
                        }
                    }
                }
            });
        }
    }
}
