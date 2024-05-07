using System;
using System.Collections.Generic;
using System.Collections.Immutable;
using System.Linq;
using System.Threading.Tasks;
using Microsoft.CodeAnalysis;
using Microsoft.CodeAnalysis.CSharp;
using Microsoft.CodeAnalysis.CSharp.Syntax;
using Microsoft.CodeAnalysis.Diagnostics;
using Projeto.Classes;

namespace ProjetoA.Analyzers
{
    internal enum NivelRisco
    {
        Alto,
        Medio,
        Baixo
    }

    internal class Vulnerabilidade
    {
        public string Tipo { get; set; }
        public string Codigo { get; set; }
        public NivelRisco Risco { get; set; }

        public Vulnerabilidade(string tipo, string codigo, NivelRisco risco)
        {
            this.Tipo = tipo;
            this.Codigo = codigo;
            this.Risco = risco;
        }
    }

    internal class SqlInjectionAnalyzer
    {
        public List<Vulnerabilidade> VulnerabilidadeAnalyze(SyntaxNode root)
        {
            // Analyze the syntax tree to identify vulnerabilities
            var vulnerabilities = new List<Vulnerabilidade>();

            // Iterate through the syntax tree nodes
            foreach (var node in root.DescendantNodes())
            {
                Task.Run(() => {

                    // Check for SQL Injection vulnerabilities
                    if (IsSqlInjectionVulnerable(node))
                    {
                        // Create a new Vulnerabilidade object
                        var vulnerability = new Vulnerabilidade(
                            "SQL Injection",
                            node.ToString(),
                            GetRiscoLevelSqlInjection(node) // implement this method to determine the risk level
                        );

                        vulnerabilities.Add(vulnerability);
                    }

                });

                
            }

            return vulnerabilities;
        }

        private bool IsSqlInjectionVulnerable(SyntaxNode node)
        {
            // Implement the logic to identify SQL Injection vulnerabilities
            // This could involve checking for specific syntax patterns, such as
            // string concatenation with user input, etc.
            throw new NotImplementedException();
        }
        private NivelRisco GetRiscoLevelSqlInjection(SyntaxNode node)
        {
            // Implement the logic to determine the risk level based on the node
            // This could involve analyzing the node's context, such as the method it's in,
            // the variables involved, etc.
            throw new NotImplementedException();
        }

        /*Continua a meter a mesma lógica para todas as outras funções*/
    }
}